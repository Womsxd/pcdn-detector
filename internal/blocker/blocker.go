// Package blocker 汇总检测层的告警事件，并在状态变化时执行封禁 / 解封。
package blocker

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/state"
	"pcdn-detect/internal/util"
)

// Blocker 汇总检测层的告警事件，并在状态变化时执行封禁/解封。
//
// 检测与封禁均以「设备 MAC + 本地端口 + 触发协议」为单位：
//   - 某「MAC + 端口 + 协议」开始告警时封禁该设备在该端口上该协议的流量
//     （UDP 触发只封 UDP，TCP 触发只封 TCP）；
//   - 该条目结束时解封；
//   - 程序退出时对所有仍处于封禁状态的条目兜底解封。
//
// 引用计数键由封禁模式决定：ban_both=true 时按「MAC + 端口 + 协议」聚合，
// 避免 IPv4 / IPv6 同端口重复封禁；ban_both=false 时再区分地址族，
// 使 v4 与 v6 各自独立封禁 / 解封。
// 防火墙命令在后台协程执行，不阻塞抓包与检测。
//
// 全 UDP 端口封禁（full_ban）：额外统计每个设备「被封禁的不同端口数」，
// 达到阈值后对该设备执行全 UDP 端口封禁（仅放行常用 / 白名单端口）；
// 被封禁端口全部解除（计数归零）时自动解除。
// 设备处于全 UDP 端口封禁状态期间，新触发的端口不再单独下发端口级封禁规则
// （其流量已被设备级全封禁覆盖），但仍纳入端口统计，使全封禁在该设备告警全部结束前保持有效；
// 触发瞬间会移除该设备此前已下发的冗余 UDP 端口级规则。
type Blocker struct {
	fw     *firewall.Firewall
	logger *log.Logger
	hide   atomic.Bool // 隐私模式：日志中隐藏设备自身的 IPv6 / 公网地址与 MAC（可运行时更新）
	events chan blockEvent
	done   chan struct{}
	wg     sync.WaitGroup

	// closeOnce 保证 Close 幂等：reload 与退出可能并发关闭同一个 Blocker，
	// 重复 close(done) 会直接 panic。
	closeOnce sync.Once

	fb FullBanConfig // 全 UDP 端口封禁模式配置
	up UPnPConfig    // UPnP 拦截配置

	// migrateMu 让「换后端」与事件处理互斥：Migrate 持写锁，handle / ForceUnban 持读锁。
	// 迁移期间事件仍在队列中排队，迁移完成后按新后端处理，不会投递给已销毁的对象。
	migrateMu sync.RWMutex

	mu     sync.Mutex
	active map[string]*banState // "mac:port:proto[:family]" -> 该条目的引用计数与 IP

	// 全端口封禁的统计（仅在事件处理协程内读写，受 mu 保护）：
	devPorts     map[string]map[uint16]int // "mac" -> 端口 -> 引用计数（v4/v6 同端口合并）
	devPortCount map[string]int            // "mac" -> 当前被封禁的不同端口数
	fullBanned   map[string]bool           // "mac" -> 是否已执行全 UDP 端口封禁

	// UPnP 拦截状态（受 mu 保护）：
	upnpBlocked map[string]bool // 黑名单模式："mac" -> 是否已拦截其 UPnP 请求
	upnpAllowed map[string]bool // 白名单模式："mac" -> 是否已放行其 UPnP 请求
	upnpAll     bool            // 白名单模式：是否已执行「拦截全部」

	devIP map[string]string // "mac" -> 最近一次已知的设备 IP（供 hook 的 {ip} 占位符使用）
}

// UPnPConfig 描述 UPnP 拦截模式。
type UPnPConfig struct {
	Enabled  bool     // 是否启用（mode != off，且防火墙已启用）
	Mode     string   // config.UPnPOn / config.UPnPDevice
	BlockAll bool     // true：拦截全部进入路由器的 UPnP（白名单模式），Targets 为放行名单；false：仅拦截 Targets
	Targets  []string // 关联设备 MAC（BlockAll 时为放行名单，否则为拦截名单）
}

// FullBanConfig 描述全 UDP 端口封禁模式。
type FullBanConfig struct {
	Enabled   bool                // 是否启用（mode != off，且防火墙已启用）
	Mode      string              // config.FullBanOn / config.FullBanDevice
	Threshold int                 // 触发阈值：被封禁的不同端口数达到该值
	Devices   map[string]struct{} // device 模式下启用全端口封禁的设备 MAC（小写）
}

// banState 记录某「MAC + 端口 + 协议」条目的引用计数（IPv4/IPv6 各算一次）与最近的设备 IP。
type banState struct {
	refs   int
	ip     string
	mac    string
	port   uint16
	proto  string
	family string // 触发地址族（v4 / v6），仅用于快照展示；ban_both=false 时同端口 v4/v6 各自独立

	// applied 表示该条目是否已在防火墙层面下发端口级封禁规则。
	// 设备若已处于全 UDP 端口封禁状态，其全部端口均被封禁，
	// 此后新触发的端口不再单独下发端口级规则（applied=false），解封 / 退出时对应跳过。
	applied bool
}

type blockEvent struct {
	ban   bool
	mac   string
	ip    string
	port  uint16
	proto string
}

// protoUDP 为 UDP 的协议名，与检测层 detector.protoName 的返回值一致。
// 全 UDP 端口封禁仅覆盖 UDP，故移除冗余端口规则时以此判断。
const protoUDP = "udp"

// NewBlocker 创建并启动封禁协调器。hide 为 true 时，日志中隐藏设备自身的地址与 MAC。
func NewBlocker(fw *firewall.Firewall, logger *log.Logger, hide bool) *Blocker {
	return NewBlockerWithUPnP(fw, logger, hide, FullBanConfig{}, UPnPConfig{})
}

// NewBlockerWithFullBan 创建并启动封禁协调器，并启用全 UDP 端口封禁模式。
// fb.Enabled 为 false 时行为与 NewBlocker 相同。
func NewBlockerWithFullBan(fw *firewall.Firewall, logger *log.Logger, hide bool, fb FullBanConfig) *Blocker {
	return NewBlockerWithUPnP(fw, logger, hide, fb, UPnPConfig{})
}

// NewBlockerWithUPnP 创建并启动封禁协调器，并启用全 UDP 端口封禁与 UPnP 拦截模式。
// fb.Enabled / up.Enabled 为 false 时对应功能不生效。
func NewBlockerWithUPnP(fw *firewall.Firewall, logger *log.Logger, hide bool, fb FullBanConfig, up UPnPConfig) *Blocker {
	if fb.Threshold <= 0 {
		fb.Threshold = 1
	}
	b := &Blocker{
		fw:           fw,
		logger:       logger,
		events:       make(chan blockEvent, 256),
		done:         make(chan struct{}),
		active:       make(map[string]*banState),
		fb:           fb,
		up:           up,
		devPorts:     make(map[string]map[uint16]int),
		devPortCount: make(map[string]int),
		fullBanned:   make(map[string]bool),
		upnpBlocked:  make(map[string]bool),
		upnpAllowed:  make(map[string]bool),
		devIP:        make(map[string]string),
	}
	b.hide.Store(hide)
	b.applyStaticUPnP()
	b.wg.Add(1)
	go b.loop()
	b.wg.Add(1)
	go b.refreshLoop()
	return b
}

// refreshLoop 周期刷新 nftables 封禁元素的内核超时：配置了 ban_ttl 时按 TTL/3 续期，
// 使进程被 SIGKILL / OOM 杀死后规则仍能在 TTL 内自动过期；未配置时每分钟检查一次
// （支持 reload 后新配置生效）。
func (b *Blocker) refreshLoop() {
	defer b.wg.Done()
	for {
		ttl := b.currentBanTTL()
		wait := time.Minute
		if ttl > 0 {
			wait = ttl / 3
			if wait < time.Second {
				wait = time.Second
			}
		}
		select {
		case <-b.done:
			return
		case <-time.After(wait):
		}
		if ttl > 0 {
			b.refreshBans()
		}
	}
}

// currentBanTTL 返回当前防火墙的封禁元素超时（与 Migrate 互斥读取，0 表示未启用）。
func (b *Blocker) currentBanTTL() time.Duration {
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()
	if b.fw == nil {
		return 0
	}
	return b.fw.BanTTL()
}

// refreshBans 重新下发当前仍生效的封禁条目，以刷新 nftables 元素超时。
// 只在 ban_ttl 启用时才有实际动作；失败只汇总告警，避免刷屏。
func (b *Blocker) refreshBans() {
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()
	if b.fw == nil || b.fw.BanTTL() <= 0 {
		return
	}

	type entry struct {
		mac   string
		ip    string
		port  uint16
		proto string
	}
	b.mu.Lock()
	bans := make([]entry, 0, len(b.active))
	for _, st := range b.active {
		if st.applied {
			bans = append(bans, entry{st.mac, st.ip, st.port, st.proto})
		}
	}
	full := make([]entry, 0, len(b.fullBanned))
	for mac := range b.fullBanned {
		full = append(full, entry{mac: mac, ip: b.devIP[mac]})
	}
	b.mu.Unlock()

	failed := 0
	for _, e := range bans {
		if err := b.fw.Ban(e.mac, e.ip, e.port, e.proto); err != nil {
			failed++
		}
	}
	for _, e := range full {
		if err := b.fw.FullBan(e.mac, e.ip); err != nil {
			failed++
		}
	}
	if failed > 0 {
		b.logger.Printf("警告：刷新 %d 条封禁元素的超时失败（可能因刷新失败而提前失效）", failed)
	}
}

// applyStaticUPnP 在启动时立即应用 UPnP 拦截：
//   - 黑名单模式（BlockAll=false）：逐个拦截 up.Targets 中的设备；
//   - 白名单模式（BlockAll=true）：先拦截全部进入路由器的 UPnP，再为 up.Targets 中的设备放行。
func (b *Blocker) applyStaticUPnP() {
	if !b.up.Enabled || b.fw == nil || !b.fw.UPnPEnabled() {
		return
	}
	if b.up.BlockAll {
		if err := b.fw.UPnPBlockAll(); err != nil {
			b.logger.Printf("拦截全部 UPnP 请求失败：%v", err)
		} else {
			b.mu.Lock()
			b.upnpAll = true
			b.mu.Unlock()
			b.logger.Printf("已拦截全部进入路由器的 UPnP 请求（目的端口：%s）", portsLabel(b.fw.UPnPPorts()))
		}
		for _, mac := range b.up.Targets {
			b.applyUPnPAllow(true, mac)
		}
		return
	}
	for _, mac := range b.up.Targets {
		b.applyUPnPBan(true, mac)
	}
}

// applyUPnPBan 执行 / 解除某设备的 UPnP 拦截（黑名单模式）。返回是否发生了实际的状态变化。
func (b *Blocker) applyUPnPBan(ban bool, mac string) bool {
	if !b.up.Enabled || b.fw == nil || !b.fw.UPnPEnabled() {
		return false
	}
	b.mu.Lock()
	already := b.upnpBlocked[mac]
	b.mu.Unlock()
	if ban == already {
		return false
	}

	if ban {
		if err := b.fw.UPnPBan(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("拦截设备 %s 的 UPnP 请求失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			return false
		}
		b.mu.Lock()
		b.upnpBlocked[mac] = true
		b.mu.Unlock()
		b.logger.Printf("已拦截设备 %s 的 UPnP 请求（目的端口：%s）",
			util.MaskDeviceMAC(b.hide.Load(), mac), portsLabel(b.fw.UPnPPorts()))
		return true
	}

	if err := b.fw.UPnPUnban(mac, b.devIPOf(mac)); err != nil {
		b.logger.Printf("解除设备 %s 的 UPnP 拦截失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
		return false
	}
	b.mu.Lock()
	delete(b.upnpBlocked, mac)
	b.mu.Unlock()
	b.logger.Printf("已解除设备 %s 的 UPnP 拦截", util.MaskDeviceMAC(b.hide.Load(), mac))
	return true
}

// applyUPnPAllow 执行 / 解除某设备的 UPnP 放行（白名单模式）。返回是否发生了实际的状态变化。
func (b *Blocker) applyUPnPAllow(allow bool, mac string) bool {
	if !b.up.Enabled || b.fw == nil || !b.fw.UPnPEnabled() {
		return false
	}
	b.mu.Lock()
	already := b.upnpAllowed[mac]
	b.mu.Unlock()
	if allow == already {
		return false
	}

	if allow {
		if err := b.fw.UPnPAllow(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("放行设备 %s 的 UPnP 请求失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			return false
		}
		b.mu.Lock()
		b.upnpAllowed[mac] = true
		b.mu.Unlock()
		b.logger.Printf("已放行设备 %s 的 UPnP 请求（目的端口：%s）",
			util.MaskDeviceMAC(b.hide.Load(), mac), portsLabel(b.fw.UPnPPorts()))
		return true
	}

	if err := b.fw.UPnPDisallow(mac, b.devIPOf(mac)); err != nil {
		b.logger.Printf("取消设备 %s 的 UPnP 放行失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
		return false
	}
	b.mu.Lock()
	delete(b.upnpAllowed, mac)
	b.mu.Unlock()
	b.logger.Printf("已取消设备 %s 的 UPnP 放行", util.MaskDeviceMAC(b.hide.Load(), mac))
	return true
}

// OnAlertStart 实现 detector.AlertSink：某设备某端口（某协议）开始告警。
func (b *Blocker) OnAlertStart(mac, ip string, port uint16, proto string) {
	b.enqueue(blockEvent{ban: true, mac: mac, ip: ip, port: port, proto: proto})
}

// OnAlertEnd 实现 detector.AlertSink：某设备某端口（某协议）告警结束。
func (b *Blocker) OnAlertEnd(mac, ip string, port uint16, proto string) {
	b.enqueue(blockEvent{ban: false, mac: mac, ip: ip, port: port, proto: proto})
}

// enqueue 非阻塞投递事件，队列满时丢弃并告警，避免拖慢检测。
func (b *Blocker) enqueue(e blockEvent) {
	select {
	case b.events <- e:
	default:
		b.logger.Printf("警告：封禁事件队列已满，丢弃 %s:%d 的事件", util.MaskDeviceMAC(b.hide.Load(), e.mac), e.port)
	}
}

func (b *Blocker) loop() {
	defer b.wg.Done()
	for {
		select {
		case <-b.done:
			return
		case e := <-b.events:
			b.handle(e)
		}
	}
}

func (b *Blocker) handle(e blockEvent) {
	// 与 Migrate 互斥：迁移期间阻塞在此，迁移完成后按新后端下发。
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()

	key := b.key(e.mac, e.port, e.proto, e.ip)
	b.mu.Lock()
	st := b.active[key]

	if e.ban {
		if st == nil {
			st = &banState{mac: e.mac, port: e.port, proto: e.proto, family: firewall.AddrFamily(e.ip)}
			b.active[key] = st
			b.bumpPortLocked(e.mac, e.port, 1)
		}
		st.refs++
		st.ip = e.ip
		if e.ip != "" {
			b.devIP[e.mac] = e.ip // 记录设备最近 IP，供 hook 的 {ip} 占位符使用
		}
		first := st.refs == 1
		// 设备已处于全 UDP 端口封禁状态时，其全部端口均已被封禁，
		// 无需再对新触发的端口下发端口级规则（标记 applied=false，解封 / 退出时对应跳过）。
		full := b.fullBanned[e.mac]
		if first {
			st.applied = !full
		}
		b.mu.Unlock()

		if first && !full {
			b.apply(true, e.mac, e.ip, e.port, e.proto)
		}
		b.maybeFullBan(e.mac, e.ip)
		return
	}

	if st == nil {
		b.mu.Unlock()
		return
	}
	st.refs--
	last := st.refs <= 0
	ip := st.ip
	proto := st.proto
	applied := st.applied
	if last {
		delete(b.active, key)
		b.bumpPortLocked(e.mac, e.port, -1)
	}
	b.mu.Unlock()

	// 仅在确实下发过端口级规则时才解封（全端口封禁期间新增的条目未单独封禁）。
	if last && applied {
		b.apply(false, e.mac, ip, e.port, proto)
	}
	b.maybeFullBan(e.mac, e.ip)
}

// bumpPortLocked 调整某设备某端口的引用计数，并维护「被封禁的不同端口数」。
// 调用方须持有 b.mu。同一端口的 IPv4 / IPv6 各算一次引用，但只计为一个端口。
func (b *Blocker) bumpPortLocked(mac string, port uint16, delta int) {
	pm := b.devPorts[mac]
	if pm == nil {
		if delta <= 0 {
			return
		}
		pm = make(map[uint16]int)
		b.devPorts[mac] = pm
	}
	n := pm[port] + delta
	if n <= 0 {
		delete(pm, port)
		if b.devPortCount[mac] > 0 {
			b.devPortCount[mac]--
		}
		if len(pm) == 0 {
			delete(b.devPorts, mac)
			delete(b.devPortCount, mac)
		}
		return
	}
	if pm[port] == 0 {
		b.devPortCount[mac]++
	}
	pm[port] = n
}

// maybeFullBan 在设备被封禁端口数达到阈值时启用全 UDP 端口封禁，归零时解除。
// device 模式下仅对 FullBanConfig.Devices 中的设备生效。
func (b *Blocker) maybeFullBan(mac, ip string) {
	if !b.fb.Enabled || b.fw == nil || !b.fw.FullBanEnabled() {
		return
	}
	if b.fb.Mode == config.FullBanDevice {
		if _, ok := b.fb.Devices[mac]; !ok {
			return
		}
	}

	b.mu.Lock()
	count := b.devPortCount[mac]
	active := b.fullBanned[mac]
	var doBan, doUnban bool
	if !active && count >= b.fb.Threshold {
		b.fullBanned[mac] = true
		doBan = true
	} else if active && count == 0 {
		delete(b.fullBanned, mac)
		doUnban = true
	}
	b.mu.Unlock()

	switch {
	case doBan:
		b.applyFull(true, mac, ip)
	case doUnban:
		b.applyFull(false, mac, ip)
	}
}

// applyFull 执行 / 解除某设备的全 UDP 端口封禁。ip 供 hook 的 {ip} 占位符使用。
func (b *Blocker) applyFull(ban bool, mac, ip string) {
	if ban {
		if err := b.fw.FullBan(mac, ip); err != nil {
			b.logger.Printf("对设备 %s 执行全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			// 回滚标记，避免后续不再重试。
			b.mu.Lock()
			delete(b.fullBanned, mac)
			b.mu.Unlock()
			return
		}
		b.logger.Printf("设备 %s 被封禁端口数达到 %d，已执行全 UDP 端口封禁（仅放行端口：%s）",
			util.MaskDeviceMAC(b.hide.Load(), mac), b.fb.Threshold, portsLabel(b.fw.FullBanAllowPorts()))
		// 全 UDP 端口封禁已覆盖该设备的全部 UDP 端口，移除此前按端口单独下发的冗余 UDP 规则。
		b.removeRedundantPortRules(mac)
		return
	}
	if err := b.fw.FullUnban(mac, ip); err != nil {
		b.logger.Printf("解除设备 %s 的全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
		return
	}
	b.logger.Printf("设备 %s 已无被封禁端口，已解除全 UDP 端口封禁", util.MaskDeviceMAC(b.hide.Load(), mac))
}

// removeRedundantPortRules 在全 UDP 端口封禁生效后，移除该设备此前按端口单独下发的冗余 UDP 封禁规则
// （这些端口已被设备级全封禁覆盖，无需再保留端口级规则）。
// 相关条目仍保留在 active / 端口统计中（其告警尚未结束），仅标记 applied=false，
// 使其告警结束 / 程序退出时不再重复解封。
// TCP 端口不在全 UDP 封禁的覆盖范围内，其端口级规则保留。
func (b *Blocker) removeRedundantPortRules(mac string) {
	type entry struct {
		ip    string
		port  uint16
		proto string
	}
	var entries []entry
	b.mu.Lock()
	for _, st := range b.active {
		if st.mac != mac || !st.applied || st.proto != protoUDP {
			continue
		}
		st.applied = false
		entries = append(entries, entry{st.ip, st.port, st.proto})
	}
	b.mu.Unlock()

	for _, e := range entries {
		b.apply(false, mac, e.ip, e.port, e.proto)
	}
}

// devIPOf 返回该设备最近一次已知的 IP（可能为空）。
func (b *Blocker) devIPOf(mac string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.devIP[mac]
}

// portsLabel 把端口列表渲染为逗号分隔字符串，用于日志。
func portsLabel(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

func (b *Blocker) apply(ban bool, mac, ip string, port uint16, proto string) {
	label := strings.ToUpper(proto)
	if ban {
		if err := b.fw.Ban(mac, ip, port, proto); err != nil {
			b.logger.Printf("封禁设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port, err)
			return
		}
		b.logger.Printf("已封禁设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port)
		return
	}
	if err := b.fw.Unban(mac, ip, port, proto); err != nil {
		b.logger.Printf("解封设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port, err)
		return
	}
	b.logger.Printf("已解封设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port)
}

// SetHide 热更新隐私模式（仅影响后续日志中的地址 / MAC 掩码，不影响封禁行为）。
func (b *Blocker) SetHide(hide bool) {
	b.hide.Store(hide)
}

// Snapshot 是封禁状态的只读快照（供 HTTP API 使用）。
type Snapshot struct {
	Bans        []BanView `json:"bans"`
	FullBanned  []string  `json:"full_banned"`
	UPnPBlocked []string  `json:"upnp_blocked"`
	UPnPAllowed []string  `json:"upnp_allowed"`
	UPnPAll     bool      `json:"upnp_all"`
}

// BanView 是一条端口级封禁条目的快照。
type BanView struct {
	MAC     string `json:"mac"`
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	Family  string `json:"family,omitempty"`
	Refs    int    `json:"refs"`
	IP      string `json:"ip,omitempty"`
	Applied bool   `json:"applied"`
}

// Snapshot 返回当前封禁状态（端口级封禁 / 全端口封禁 / UPnP 拦截放行）。
func (b *Blocker) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := Snapshot{UPnPAll: b.upnpAll}
	for _, st := range b.active {
		out.Bans = append(out.Bans, BanView{
			MAC: st.mac, Port: st.port, Proto: st.proto, Family: st.family,
			Refs: st.refs, IP: st.ip, Applied: st.applied,
		})
	}
	sort.Slice(out.Bans, func(i, j int) bool {
		if out.Bans[i].MAC != out.Bans[j].MAC {
			return out.Bans[i].MAC < out.Bans[j].MAC
		}
		if out.Bans[i].Port != out.Bans[j].Port {
			return out.Bans[i].Port < out.Bans[j].Port
		}
		return out.Bans[i].Proto < out.Bans[j].Proto
	})
	for mac, on := range b.fullBanned {
		if on {
			out.FullBanned = append(out.FullBanned, mac)
		}
	}
	for mac, on := range b.upnpBlocked {
		if on {
			out.UPnPBlocked = append(out.UPnPBlocked, mac)
		}
	}
	for mac, on := range b.upnpAllowed {
		if on {
			out.UPnPAllowed = append(out.UPnPAllowed, mac)
		}
	}
	sort.Strings(out.FullBanned)
	sort.Strings(out.UPnPBlocked)
	sort.Strings(out.UPnPAllowed)
	return out
}

// ForceUnban 手动解封某 MAC 在指定协议下的端口，返回移除的封禁条目数。
// 仅对已下发端口级规则的条目调用防火墙解封（被全端口封禁覆盖的条目无需单独解封）。
func (b *Blocker) ForceUnban(mac string, port uint16, proto string) (int, error) {
	// 与 Migrate 互斥：避免迁移中途对旧 / 新后端各下发一半解封命令。
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()

	if b.fw == nil {
		return 0, errors.New("防火墙未启用")
	}
	macAddr, err := netutil.ParseMAC(mac)
	if err != nil {
		return 0, fmt.Errorf("MAC 无效：%q", mac)
	}
	mac = macAddr.String()
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != protoUDP && proto != "tcp" {
		return 0, fmt.Errorf("proto 无效：%q（可选 udp / tcp）", proto)
	}

	type target struct {
		ip    string
		proto string
	}
	var targets []target
	removed := 0
	b.mu.Lock()
	for key, st := range b.active {
		if st.mac != mac || st.port != port || st.proto != proto {
			continue
		}
		if st.applied {
			targets = append(targets, target{st.ip, st.proto})
		}
		delete(b.active, key)
		b.bumpPortLocked(mac, port, -1)
		removed++
	}
	b.mu.Unlock()

	var firstErr error
	for _, t := range targets {
		label := strings.ToUpper(t.proto)
		if err := b.fw.Unban(mac, t.ip, port, t.proto); err != nil {
			b.logger.Printf("手动解封设备 %s 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), label, port, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		b.logger.Printf("已手动解封设备 %s 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), mac), label, port)
	}
	return removed, firstErr
}

// BlockState 导出当前封禁状态（供 reload 重启继承）。
func (b *Blocker) BlockState() state.BlockState {
	b.mu.Lock()
	defer b.mu.Unlock()

	var s state.BlockState
	for _, st := range b.active {
		mac, err := netutil.ParseMAC(st.mac)
		if err != nil {
			continue
		}
		s.Bans = append(s.Bans, state.BanEntry{
			MAC: mac, Port: st.port, Proto: protoToU8(st.proto),
			Family: familyToU8(st.family), IP: parseAddr(st.ip), Refs: st.refs, Applied: st.applied,
		})
	}
	for mac, on := range b.fullBanned {
		if !on {
			continue
		}
		m, err := netutil.ParseMAC(mac)
		if err != nil {
			continue
		}
		s.FullBanned = append(s.FullBanned, state.FullBanEntry{MAC: m, IP: parseAddr(b.devIP[mac])})
	}
	s.UPnPBlocked = macsOf(b.upnpBlocked)
	s.UPnPAllowed = macsOf(b.upnpAllowed)
	s.UPnPAll = b.upnpAll
	return s
}

// Restore 按状态还原并重新下发封禁（启动继承时调用，使用当前防火墙后端）。
// 与构造期的 applyStaticUPnP 幂等协作：已存在的条目 / 状态不会重复下发。
func (b *Blocker) Restore(s state.BlockState) {
	if b.fw == nil {
		return
	}
	for _, e := range s.Bans {
		mac := e.MAC.String()
		proto := u8ToProto(e.Proto)
		ip := addrToString(e.IP)
		key := b.key(mac, e.Port, proto, ip)
		b.mu.Lock()
		if _, ok := b.active[key]; ok {
			b.mu.Unlock()
			continue
		}
		refs := e.Refs
		if refs < 1 {
			refs = 1
		}
		b.active[key] = &banState{mac: mac, port: e.Port, proto: proto, family: u8ToFamily(e.Family), ip: ip, refs: refs, applied: e.Applied}
		b.bumpPortLocked(mac, e.Port, 1)
		b.mu.Unlock()

		if e.Applied {
			if err := b.fw.Ban(mac, ip, e.Port, proto); err != nil {
				b.logger.Printf("继承封禁设备 %s 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), strings.ToUpper(proto), e.Port, err)
			}
		}
	}
	for _, e := range s.FullBanned {
		mac := e.MAC.String()
		b.mu.Lock()
		if b.fullBanned[mac] {
			b.mu.Unlock()
			continue
		}
		b.fullBanned[mac] = true
		b.mu.Unlock()
		if err := b.fw.FullBan(mac, addrToString(e.IP)); err != nil {
			b.logger.Printf("继承全 UDP 端口封禁设备 %s 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			b.mu.Lock()
			delete(b.fullBanned, mac)
			b.mu.Unlock()
		}
	}
	for _, m := range s.UPnPBlocked {
		b.applyUPnPBan(true, m.String())
	}
	for _, m := range s.UPnPAllowed {
		b.applyUPnPAllow(true, m.String())
	}
	if s.UPnPAll {
		b.mu.Lock()
		already := b.upnpAll
		b.mu.Unlock()
		if !already {
			if err := b.fw.UPnPBlockAll(); err != nil {
				b.logger.Printf("继承 UPnP 全量拦截失败：%v", err)
			} else {
				b.mu.Lock()
				b.upnpAll = true
				b.mu.Unlock()
			}
		}
	}
}

// Migrate 在暂停事件处理的前提下把防火墙原地迁移到新配置，返回新后端对象：
//   - 先按旧后端逐条解封并清理旧规则（break），再调用 build 建新后端并重新下发（make）；
//   - Blocker 对象本身不变，因此检测层 sink 与 HTTP 持有的指针始终有效；迁移期间到达的
//     告警事件会排在队列里，迁移完成后按新后端处理，不会被投递给已销毁的对象；
//   - 迁移失败时内存状态保持不变并原样返回错误（调用方通常回退到重启，按状态文件恢复）。
//
// 调用方须保证 build 返回的配置（fb / up）与 nfw 一致。
func (b *Blocker) Migrate(build func() (*firewall.Firewall, FullBanConfig, UPnPConfig, error)) (*firewall.Firewall, error) {
	b.migrateMu.Lock()
	defer b.migrateMu.Unlock()

	snap := b.BlockState()

	// 1) 解除旧后端规则并清理其残留（nftables 需整表删除，hook / iptables 主要靠逐条解封）。
	if b.fw != nil {
		b.unbanAllRules()
		b.fw.Cleanup()
	}

	// 2) 建新后端。失败时保留原 fw 与状态，由调用方决定回退方式。
	nfw, fb, up, err := build()
	if err != nil {
		return nil, err
	}
	b.fw, b.fb, b.up = nfw, fb, up

	// 3) 清空内存状态后按快照重建：Restore 会跳过已存在的条目，故必须先清空；
	//    UPnP 的静态配置（名单 / 全量拦截）不在快照里，需按新配置重新应用。
	b.mu.Lock()
	b.resetStateLocked()
	b.mu.Unlock()
	b.applyStaticUPnP()
	b.Restore(snap)
	return nfw, nil
}

func protoToU8(proto string) uint8 {
	if proto == "tcp" {
		return netutil.ProtoTCP
	}
	return netutil.ProtoUDP
}

func u8ToProto(p uint8) string {
	if p == netutil.ProtoTCP {
		return "tcp"
	}
	return protoUDP
}

func familyToU8(f string) uint8 {
	switch f {
	case "v4":
		return state.FamilyV4
	case "v6":
		return state.FamilyV6
	default:
		return state.FamilyNone
	}
}

func u8ToFamily(f uint8) string {
	switch f {
	case state.FamilyV4:
		return "v4"
	case state.FamilyV6:
		return "v6"
	default:
		return ""
	}
}

func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

func addrToString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.Unmap().String()
}

func macsOf(m map[string]bool) []netutil.MAC {
	var out []netutil.MAC
	for s, on := range m {
		if !on {
			continue
		}
		if mac, err := netutil.ParseMAC(s); err == nil {
			out = append(out, mac)
		}
	}
	return out
}

// Close 停止协调器，并对所有仍封禁中的条目（含全 UDP 端口封禁）兜底解封。
// 幂等：重复调用（如 reload 与退出并发）不会重复关闭通道或重复解封。
func (b *Blocker) Close() {
	b.closeOnce.Do(b.stopAndUnban)
}

// stopAndUnban 停止事件处理协程，并对仍封禁中的条目兜底解封（Close 的实现体）。
func (b *Blocker) stopAndUnban() {
	close(b.done)
	// 先等事件协程退出，再取写锁。顺序不能反：handler 在 handle 里要先拿读锁，
	// 若本函数先持写锁再 wg.Wait，正在等读锁的那次 handle 会永久阻塞（Go RWMutex 写者优先）。
	b.wg.Wait()

	b.migrateMu.Lock()
	defer b.migrateMu.Unlock()
	b.unbanAllRules()
	b.mu.Lock()
	b.resetStateLocked()
	b.mu.Unlock()
}

// unbanAllRules 按当前内存状态对旧后端逐条解封，只下发命令、不改动内存状态。
// 供 Close（退出兜底）与 Migrate（换后端）复用。
func (b *Blocker) unbanAllRules() {
	if b.fw == nil {
		return
	}

	b.mu.Lock()
	type target struct {
		mac   string
		ip    string
		port  uint16
		proto string
	}
	targets := make([]target, 0, len(b.active))
	for _, st := range b.active {
		if !st.applied {
			continue // 该条目未被单独下发端口级规则（全端口封禁覆盖），无需解封
		}
		targets = append(targets, target{st.mac, st.ip, st.port, st.proto})
	}
	fullBanned := make([]string, 0, len(b.fullBanned))
	for mac := range b.fullBanned {
		fullBanned = append(fullBanned, mac)
	}
	upnpBlocked := make([]string, 0, len(b.upnpBlocked))
	for mac := range b.upnpBlocked {
		upnpBlocked = append(upnpBlocked, mac)
	}
	upnpAllowed := make([]string, 0, len(b.upnpAllowed))
	for mac := range b.upnpAllowed {
		upnpAllowed = append(upnpAllowed, mac)
	}
	upnpAll := b.upnpAll
	b.mu.Unlock()

	for _, t := range targets {
		label := strings.ToUpper(t.proto)
		if err := b.fw.Unban(t.mac, t.ip, t.port, t.proto); err != nil {
			b.logger.Printf("解封设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), t.mac), util.MaskDeviceIP(b.hide.Load(), t.ip), label, t.port, err)
			continue
		}
		b.logger.Printf("已解封设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), t.mac), util.MaskDeviceIP(b.hide.Load(), t.ip), label, t.port)
	}
	// 全端口封禁条目兜底解除（端口级解封不影响设备级全封禁规则）。
	for _, mac := range fullBanned {
		if err := b.fw.FullUnban(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("解除设备 %s 的全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			continue
		}
		b.logger.Printf("已解除设备 %s 的全 UDP 端口封禁", util.MaskDeviceMAC(b.hide.Load(), mac))
	}
	// UPnP 拦截条目解除（黑名单模式）。
	for _, mac := range upnpBlocked {
		if err := b.fw.UPnPUnban(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("解除设备 %s 的 UPnP 拦截失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			continue
		}
		b.logger.Printf("已解除设备 %s 的 UPnP 拦截", util.MaskDeviceMAC(b.hide.Load(), mac))
	}
	// UPnP 放行条目与全量拦截解除（白名单模式）：先取消放行，再解除全量拦截。
	for _, mac := range upnpAllowed {
		if err := b.fw.UPnPDisallow(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("取消设备 %s 的 UPnP 放行失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			continue
		}
		b.logger.Printf("已取消设备 %s 的 UPnP 放行", util.MaskDeviceMAC(b.hide.Load(), mac))
	}
	if upnpAll {
		if err := b.fw.UPnPUnblockAll(); err != nil {
			b.logger.Printf("解除全部 UPnP 拦截失败：%v", err)
		} else {
			b.logger.Printf("已解除全部 UPnP 拦截")
		}
	}
}

// resetStateLocked 清空运行期状态（调用方须持有 b.mu）。devIP 不清：
// 它只是「最近一次已知的设备 IP」，换后端后 hook 的 {ip} 占位符仍可继续使用。
func (b *Blocker) resetStateLocked() {
	b.active = make(map[string]*banState)
	b.devPorts = make(map[string]map[uint16]int)
	b.devPortCount = make(map[string]int)
	b.fullBanned = make(map[string]bool)
	b.upnpBlocked = make(map[string]bool)
	b.upnpAllowed = make(map[string]bool)
	b.upnpAll = false
}

func blockKey(mac string, port uint16) string {
	return mac + ":" + strconv.Itoa(int(port))
}

// key 返回条目的引用计数键（始终包含触发协议，使 UDP 与 TCP 独立封禁 / 解封）：
//   - 同时封禁 v4/v6（ban_both=true）时按「MAC + 端口 + 协议」聚合，v4/v6 共用一次封禁；
//   - 单独封禁（ban_both=false）时进一步区分地址族，使 v4 与 v6 各自独立封禁 / 解封。
func (b *Blocker) key(mac string, port uint16, proto, ip string) string {
	k := blockKey(mac, port) + ":" + proto
	if !b.fw.BanBoth() {
		k += ":" + firewall.AddrFamily(ip)
	}
	return k
}

// 确保 Blocker 实现 detector.AlertSink。
var _ detector.AlertSink = (*Blocker)(nil)
