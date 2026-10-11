// Package blocker 汇总检测层的告警事件，并在状态变化时执行封禁 / 解封。
package blocker

import (
	"log"
	"strconv"
	"strings"
	"sync"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/firewall"
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
type Blocker struct {
	fw     *firewall.Firewall
	logger *log.Logger
	hide   bool // 隐私模式：日志中隐藏设备自身的 IPv6 / 公网地址与 MAC
	events chan blockEvent
	done   chan struct{}
	wg     sync.WaitGroup

	fb FullBanConfig // 全 UDP 端口封禁模式配置
	up UPnPConfig    // UPnP 拦截配置

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
	refs  int
	ip    string
	mac   string
	port  uint16
	proto string
}

type blockEvent struct {
	ban   bool
	mac   string
	ip    string
	port  uint16
	proto string
}

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
		hide:         hide,
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
	}
	b.applyStaticUPnP()
	b.wg.Add(1)
	go b.loop()
	return b
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
		if err := b.fw.UPnPBan(mac); err != nil {
			b.logger.Printf("拦截设备 %s 的 UPnP 请求失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
			return false
		}
		b.mu.Lock()
		b.upnpBlocked[mac] = true
		b.mu.Unlock()
		b.logger.Printf("已拦截设备 %s 的 UPnP 请求（目的端口：%s）",
			util.MaskDeviceMAC(b.hide, mac), portsLabel(b.fw.UPnPPorts()))
		return true
	}

	if err := b.fw.UPnPUnban(mac); err != nil {
		b.logger.Printf("解除设备 %s 的 UPnP 拦截失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
		return false
	}
	b.mu.Lock()
	delete(b.upnpBlocked, mac)
	b.mu.Unlock()
	b.logger.Printf("已解除设备 %s 的 UPnP 拦截", util.MaskDeviceMAC(b.hide, mac))
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
		if err := b.fw.UPnPAllow(mac); err != nil {
			b.logger.Printf("放行设备 %s 的 UPnP 请求失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
			return false
		}
		b.mu.Lock()
		b.upnpAllowed[mac] = true
		b.mu.Unlock()
		b.logger.Printf("已放行设备 %s 的 UPnP 请求（目的端口：%s）",
			util.MaskDeviceMAC(b.hide, mac), portsLabel(b.fw.UPnPPorts()))
		return true
	}

	if err := b.fw.UPnPDisallow(mac); err != nil {
		b.logger.Printf("取消设备 %s 的 UPnP 放行失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
		return false
	}
	b.mu.Lock()
	delete(b.upnpAllowed, mac)
	b.mu.Unlock()
	b.logger.Printf("已取消设备 %s 的 UPnP 放行", util.MaskDeviceMAC(b.hide, mac))
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
		b.logger.Printf("警告：封禁事件队列已满，丢弃 %s:%d 的事件", util.MaskDeviceMAC(b.hide, e.mac), e.port)
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
	key := b.key(e.mac, e.port, e.proto, e.ip)
	b.mu.Lock()
	st := b.active[key]

	if e.ban {
		if st == nil {
			st = &banState{mac: e.mac, port: e.port, proto: e.proto}
			b.active[key] = st
			b.bumpPortLocked(e.mac, e.port, 1)
		}
		st.refs++
		st.ip = e.ip
		first := st.refs == 1
		b.mu.Unlock()

		if first {
			b.apply(true, e.mac, e.ip, e.port, e.proto)
		}
		b.maybeFullBan(e.mac)
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
	if last {
		delete(b.active, key)
		b.bumpPortLocked(e.mac, e.port, -1)
	}
	b.mu.Unlock()

	if last {
		b.apply(false, e.mac, ip, e.port, proto)
	}
	b.maybeFullBan(e.mac)
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
func (b *Blocker) maybeFullBan(mac string) {
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
		b.applyFull(true, mac)
	case doUnban:
		b.applyFull(false, mac)
	}
}

// applyFull 执行 / 解除某设备的全 UDP 端口封禁。
func (b *Blocker) applyFull(ban bool, mac string) {
	if ban {
		if err := b.fw.FullBan(mac); err != nil {
			b.logger.Printf("对设备 %s 执行全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
			// 回滚标记，避免后续不再重试。
			b.mu.Lock()
			delete(b.fullBanned, mac)
			b.mu.Unlock()
			return
		}
		b.logger.Printf("设备 %s 被封禁端口数达到 %d，已执行全 UDP 端口封禁（仅放行端口：%s）",
			util.MaskDeviceMAC(b.hide, mac), b.fb.Threshold, portsLabel(b.fw.FullBanAllowPorts()))
		return
	}
	if err := b.fw.FullUnban(mac); err != nil {
		b.logger.Printf("解除设备 %s 的全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
		return
	}
	b.logger.Printf("设备 %s 已无被封禁端口，已解除全 UDP 端口封禁", util.MaskDeviceMAC(b.hide, mac))
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
			b.logger.Printf("封禁设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide, mac), util.MaskDeviceIP(b.hide, ip), label, port, err)
			return
		}
		b.logger.Printf("已封禁设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide, mac), util.MaskDeviceIP(b.hide, ip), label, port)
		return
	}
	if err := b.fw.Unban(mac, ip, port, proto); err != nil {
		b.logger.Printf("解封设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide, mac), util.MaskDeviceIP(b.hide, ip), label, port, err)
		return
	}
	b.logger.Printf("已解封设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide, mac), util.MaskDeviceIP(b.hide, ip), label, port)
}

// Close 停止协调器，并对所有仍封禁中的条目（含全 UDP 端口封禁）兜底解封。
func (b *Blocker) Close() {
	close(b.done)
	b.wg.Wait()

	b.mu.Lock()
	type target struct {
		mac   string
		ip    string
		port  uint16
		proto string
	}
	targets := make([]target, 0, len(b.active))
	for _, st := range b.active {
		targets = append(targets, target{st.mac, st.ip, st.port, st.proto})
	}
	b.active = make(map[string]*banState)
	fullBanned := make([]string, 0, len(b.fullBanned))
	for mac := range b.fullBanned {
		fullBanned = append(fullBanned, mac)
	}
	b.fullBanned = make(map[string]bool)
	upnpBlocked := make([]string, 0, len(b.upnpBlocked))
	for mac := range b.upnpBlocked {
		upnpBlocked = append(upnpBlocked, mac)
	}
	b.upnpBlocked = make(map[string]bool)
	upnpAllowed := make([]string, 0, len(b.upnpAllowed))
	for mac := range b.upnpAllowed {
		upnpAllowed = append(upnpAllowed, mac)
	}
	b.upnpAllowed = make(map[string]bool)
	upnpAll := b.upnpAll
	b.upnpAll = false
	b.mu.Unlock()

	for _, t := range targets {
		label := strings.ToUpper(t.proto)
		if err := b.fw.Unban(t.mac, t.ip, t.port, t.proto); err != nil {
			b.logger.Printf("退出时解封设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide, t.mac), util.MaskDeviceIP(b.hide, t.ip), label, t.port, err)
			continue
		}
		b.logger.Printf("退出时已解封设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide, t.mac), util.MaskDeviceIP(b.hide, t.ip), label, t.port)
	}
	// 全端口封禁条目兜底解除（端口级解封不影响设备级全封禁规则）。
	for _, mac := range fullBanned {
		if err := b.fw.FullUnban(mac); err != nil {
			b.logger.Printf("退出时解除设备 %s 的全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
			continue
		}
		b.logger.Printf("退出时已解除设备 %s 的全 UDP 端口封禁", util.MaskDeviceMAC(b.hide, mac))
	}
	// UPnP 拦截条目兜底解除（黑名单模式）。
	for _, mac := range upnpBlocked {
		if err := b.fw.UPnPUnban(mac); err != nil {
			b.logger.Printf("退出时解除设备 %s 的 UPnP 拦截失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
			continue
		}
		b.logger.Printf("退出时已解除设备 %s 的 UPnP 拦截", util.MaskDeviceMAC(b.hide, mac))
	}
	// UPnP 放行条目与全量拦截兜底解除（白名单模式）：先取消放行，再解除全量拦截。
	for _, mac := range upnpAllowed {
		if err := b.fw.UPnPDisallow(mac); err != nil {
			b.logger.Printf("退出时取消设备 %s 的 UPnP 放行失败：%v", util.MaskDeviceMAC(b.hide, mac), err)
			continue
		}
		b.logger.Printf("退出时已取消设备 %s 的 UPnP 放行", util.MaskDeviceMAC(b.hide, mac))
	}
	if upnpAll {
		if err := b.fw.UPnPUnblockAll(); err != nil {
			b.logger.Printf("退出时解除全部 UPnP 拦截失败：%v", err)
		} else {
			b.logger.Printf("退出时已解除全部 UPnP 拦截")
		}
	}
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
