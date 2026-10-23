// Package blocker 汇总检测层的告警事件，并在状态变化时执行封禁 / 解封。
package blocker

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/logx"
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
	logger *logx.Logger
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
func NewBlocker(fw *firewall.Firewall, logger *logx.Logger, hide bool) *Blocker {
	return NewBlockerWithUPnP(fw, logger, hide, FullBanConfig{}, UPnPConfig{})
}

// NewBlockerWithFullBan 创建并启动封禁协调器，并启用全 UDP 端口封禁模式。
// fb.Enabled 为 false 时行为与 NewBlocker 相同。
func NewBlockerWithFullBan(fw *firewall.Firewall, logger *logx.Logger, hide bool, fb FullBanConfig) *Blocker {
	return NewBlockerWithUPnP(fw, logger, hide, fb, UPnPConfig{})
}

// NewBlockerWithUPnP 创建并启动封禁协调器，并启用全 UDP 端口封禁与 UPnP 拦截模式。
// fb.Enabled / up.Enabled 为 false 时对应功能不生效。
func NewBlockerWithUPnP(fw *firewall.Firewall, logger *logx.Logger, hide bool, fb FullBanConfig, up UPnPConfig) *Blocker {
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
		b.logger.Warnf("警告：封禁事件队列已满，丢弃 %s:%d 的事件", util.MaskDeviceMAC(b.hide.Load(), e.mac), e.port)
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
			b.logger.Errorf("封禁设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port, err)
			return
		}
		b.logger.Infof("已封禁设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port)
		return
	}
	if err := b.fw.Unban(mac, ip, port, proto); err != nil {
		b.logger.Errorf("解封设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port, err)
		return
	}
	b.logger.Infof("已解封设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), mac), util.MaskDeviceIP(b.hide.Load(), ip), label, port)
}

// SetHide 热更新隐私模式（仅影响后续日志中的地址 / MAC 掩码，不影响封禁行为）。
func (b *Blocker) SetHide(hide bool) {
	b.hide.Store(hide)
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
			b.logger.Errorf("解封设备 %s(%s) 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), t.mac), util.MaskDeviceIP(b.hide.Load(), t.ip), label, t.port, err)
			continue
		}
		b.logger.Infof("已解封设备 %s(%s) 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), t.mac), util.MaskDeviceIP(b.hide.Load(), t.ip), label, t.port)
	}
	// 全端口封禁条目兜底解除（端口级解封不影响设备级全封禁规则）。
	for _, mac := range fullBanned {
		if err := b.fw.FullUnban(mac, b.devIPOf(mac)); err != nil {
			b.logger.Errorf("解除设备 %s 的全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			continue
		}
		b.logger.Infof("已解除设备 %s 的全 UDP 端口封禁", util.MaskDeviceMAC(b.hide.Load(), mac))
	}
	// UPnP 拦截条目解除（黑名单模式）。
	for _, mac := range upnpBlocked {
		if err := b.fw.UPnPUnban(mac, b.devIPOf(mac)); err != nil {
			b.logger.Errorf("解除设备 %s 的 UPnP 拦截失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			continue
		}
		b.logger.Infof("已解除设备 %s 的 UPnP 拦截", util.MaskDeviceMAC(b.hide.Load(), mac))
	}
	// UPnP 放行条目与全量拦截解除（白名单模式）：先取消放行，再解除全量拦截。
	for _, mac := range upnpAllowed {
		if err := b.fw.UPnPDisallow(mac, b.devIPOf(mac)); err != nil {
			b.logger.Errorf("取消设备 %s 的 UPnP 放行失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			continue
		}
		b.logger.Infof("已取消设备 %s 的 UPnP 放行", util.MaskDeviceMAC(b.hide.Load(), mac))
	}
	if upnpAll {
		if err := b.fw.UPnPUnblockAll(); err != nil {
			b.logger.Errorf("解除全部 UPnP 拦截失败：%v", err)
		} else {
			b.logger.Infof("已解除全部 UPnP 拦截")
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
