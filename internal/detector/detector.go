// Package detector 维护滑动窗口内的连接统计，并在超过阈值时告警。
package detector

import (
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/netutil"
)

// map 收缩（compaction）参数。
//
// Go 的 map 删除元素后不会收缩底层 bucket 数组：一旦因突发增长到很大，即使之后元素
// 被大量删除（如窗口过期、设备下线），其 bucket 内存仍会长期驻留，是长期运行进程内存
// 不回落的主因。当当前元素数降到峰值的一定比例以下时重建该 map，即可把多余 bucket
// 归还运行时；两级阈值用于避免小 map 的抖动与“刚缩又涨”的反复重建。
const (
	// minCompactPeak：元素数峰值低于该值时不做重建（节省有限，却会引入额外抖动）。
	minCompactPeak = 64
	// compactRatio：当前元素数 ≤ 峰值/compactRatio 时才重建（取 4 即缩到峰值 1/4 以下）。
	compactRatio = 4
)

// compactMap 在 map 因大量删除而明显“缩水”时重建，释放不再随删除回收的 bucket 内存。
// peak 为该 map 自上次重建以来的元素数峰值。仅当 peak 足够大且当前元素数已降到峰值的
// 1/compactRatio 以下时才重建；否则原样返回（ok 为 false）。
func compactMap[K comparable, V any](m map[K]V, peak int) (map[K]V, bool) {
	if peak < minCompactPeak || len(m)*compactRatio > peak {
		return m, false
	}
	nm := make(map[K]V, len(m))
	for k, v := range m {
		nm[k] = v
	}
	return nm, true
}

// Observation 是一条抓包解析后的观测记录，由抓包层交给检测层。
//
// 地址使用 netip.Addr（值类型、可比较）：抓包层可直接由报文原始字节构造，
// 既零分配，又能直接作为 map 键，避免为每个对端保留 IP 字符串。
type Observation struct {
	MAC       netutil.MAC // 设备 MAC（6 字节值类型，零分配且可作 map 键）
	IP        netip.Addr  // 设备 IP
	LocalPort uint16      // 设备本地端口
	RemoteIP  netip.Addr  // 远端 IP
	Up        bool        // true: 设备 -> 远端（上行）; false: 远端 -> 设备（下行）
	V6        bool        // true 表示该报文为 IPv6
	Proto     uint8       // 传输层协议（netutil.ProtoTCP / netutil.ProtoUDP）
	Length    int         // 报文长度（字节）
	TS        time.Time
}

// protoName 返回传输层协议的展示名（"tcp" / "udp"）。
// 观测只会是 TCP 或 UDP；非 TCP 一律按 UDP 处理（也便于测试构造）。
func protoName(proto uint8) string {
	if proto == netutil.ProtoTCP {
		return "tcp"
	}
	return "udp"
}

// AlertSink 接收某「设备 + 本地端口 + 协议」的告警开始 / 结束事件，用于对接防火墙等外部动作。
// proto 为触发该告警的传输层协议（"udp" / "tcp"），供封禁层按触发协议精确封禁。
type AlertSink interface {
	OnAlertStart(mac, ip string, port uint16, proto string)
	OnAlertEnd(mac, ip string, port uint16, proto string)
}

// Detector 维护滑动窗口内的连接统计，并在超过阈值时告警。
type Detector struct {
	mu            sync.Mutex
	devices       map[netutil.MAC]*device
	devicesPeak   int           // devices 的元素数峰值，用于在明显缩小时重建该 map 以回收内存
	threshold     int           // 触发次数：同一设备同一端口在窗口内出现的不同远端 IP 数量阈值
	window        time.Duration // 检测时长（滑动窗口）
	alertDuration time.Duration // 首次告警后持续提示的最长时间
	sink          AlertSink     // 告警回调（nil 表示不回调）
	logger        *log.Logger
	hide          bool // 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC
	lowMemory     bool // 低内存模式：端口触发告警后清空对端列表且不再记录新对端
	peerLimit     int  // 单端口对端记录上限；0 表示不限制（关闭）
	maxPorts      int  // 单设备端口条目上限；0 表示不限制（关闭）

	// 黑白名单过滤器（nil 表示不过滤）。读发生在抓包热路径（不加 d.mu），热更新时由
	// SetFilter 整体替换指针，故必须用原子指针：DeviceFilter 构造后不再修改，替换后可安全共用。
	filter atomic.Pointer[filter.DeviceFilter]

	// 端口上限的可观测计数（累计值）：
	portEvictions int64 // 因达到端口上限而提前过期的端口条目数
	portDrops     int64 // 因达到上限且无端口可淘汰而丢弃的新端口报文数

	alerts int
}

// SetSink 设置告警回调。可在运行时调用（加锁，供 reload 重建 blocker 后换绑）。
func (d *Detector) SetSink(s AlertSink) {
	d.mu.Lock()
	d.sink = s
	d.mu.Unlock()
}

// SetParams 热更新检测参数：触发阈值、检测时长与持续提示时长。
// 对端上限低于新阈值时同步抬到阈值：否则端口最多只记录旧上限个对端，永远达不到阈值，告警无法触发。
func (d *Detector) SetParams(threshold int, window, alertDuration time.Duration) {
	d.mu.Lock()
	d.threshold = threshold
	if d.peerLimit > 0 && d.peerLimit < threshold {
		d.peerLimit = threshold
	}
	d.window = window
	d.alertDuration = alertDuration
	d.mu.Unlock()
}

// SetHide 热更新隐私模式（仅影响后续告警日志的地址掩码）。
func (d *Detector) SetHide(hide bool) {
	d.mu.Lock()
	d.hide = hide
	d.mu.Unlock()
}

// SetLowMemory 热更新低内存模式。
func (d *Detector) SetLowMemory(lowMemory bool) {
	d.mu.Lock()
	d.lowMemory = lowMemory
	d.mu.Unlock()
}

// SetPeerLimit 热更新单端口对端记录上限（0 表示不限制）。
func (d *Detector) SetPeerLimit(limit int) {
	d.mu.Lock()
	d.peerLimit = limit
	d.mu.Unlock()
}

// SetMaxPorts 热更新单设备端口条目上限（0 表示不限制）。
// 调小后由后续 Scan 把超出的端口条目收敛到新上限，无需重启。
func (d *Detector) SetMaxPorts(limit int) {
	d.mu.Lock()
	d.maxPorts = limit
	d.mu.Unlock()
}

// SetFilter 热替换名单过滤器（供 reload 热应用 [filter] 变更）。
// 仅替换指针且与 Observe 的无锁读通过原子指针同步，不影响检测状态本身。
func (d *Detector) SetFilter(f *filter.DeviceFilter) {
	d.filter.Store(f)
}

// NewDetector 创建一个检测器。filter 为 nil 时不做名单过滤。
// hide 为 true 时启用隐私模式，日志中隐藏设备自身的 IPv6 / 公网地址与 MAC。
// lowMemory 为 true 时启用低内存模式：某「设备 + 端口」一旦触发告警，即清空对端列表并
// 停止记录新对端，只保留触发状态（告警续期 / 累计流量）。
// peerLimit 为单个端口的对端记录上限（0 表示不限制）；达到上限后不再记录新的对端 IP，
// 已有对端仍照常刷新与累计，且端口级流量仍完整累计。
// maxPorts 为单设备端口条目上限（0 表示不限制）：达到上限时提前过期一部分端口为新端口腾位置。
func NewDetector(threshold int, window, alertDuration time.Duration, flt *filter.DeviceFilter, logger *log.Logger, hide bool, lowMemory bool, peerLimit int, maxPorts int) *Detector {
	d := &Detector{
		devices:       make(map[netutil.MAC]*device),
		threshold:     threshold,
		window:        window,
		alertDuration: alertDuration,
		logger:        logger,
		hide:          hide,
		lowMemory:     lowMemory,
		peerLimit:     peerLimit,
		maxPorts:      maxPorts,
	}
	d.filter.Store(flt)
	return d
}

// Observe 记录一条观测。对端为非公网地址的记录由抓包层过滤，不会传入。
func (d *Detector) Observe(o Observation) {
	// 黑白名单：不参与检测的「设备 MAC + 端口」直接丢弃。
	// AllowKey 对 nil 接收者一律放行，故未配置名单时（Load 返回 nil）无需额外判空。
	if !d.filter.Load().AllowKey(o.MAC, o.LocalPort) {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	dev := d.devices[o.MAC]
	if dev == nil {
		dev = &device{}
		d.devices[o.MAC] = dev
	}

	key := portKey{port: o.LocalPort, proto: o.Proto}
	nowNano := o.TS.UnixNano()

	// 对端键按地址族选用最紧凑的表示（IPv4 用 As4() 的 4 字节，IPv6 用 As16() 的 16 字节），
	// 零分配；地址族同时也决定使用哪张端口表。
	if o.V6 {
		ps := portFor(d, dev, &dev.v6, key, nowNano)
		if ps == nil {
			d.dropNewPort(o)
			return
		}
		ps.observe(peerKey6(o.RemoteIP.As16()), o, d.peerLimit, d.lowMemory)
		return
	}
	ps := portFor(d, dev, &dev.v4, key, nowNano)
	if ps == nil {
		d.dropNewPort(o)
		return
	}
	ps.observe(peerKey4(o.RemoteIP.Unmap().As4()), o, d.peerLimit, d.lowMemory)
}

// Scan 清理超时对端并检查是否触发告警，需定期调用。
func (d *Detector) Scan(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nowNano := now.UnixNano()
	windowNano := int64(d.window)

	// 两次 Scan 之间只有 Observe 会增加元素（清理只发生在本函数内），故进入本轮时的长度
	// 即上一区间的元素数峰值，据此记录各级 map 的峰值，用于判断是否需要重建以回收内存。
	if len(d.devices) > d.devicesPeak {
		d.devicesPeak = len(d.devices)
	}

	for mac, dev := range d.devices {
		dev.v4.scan(d, mac, false, now, nowNano, windowNano)
		dev.v6.scan(d, mac, true, now, nowNano, windowNano)
		// 上限被调小（热更新）时，在本轮扫描把超出的端口收敛到新上限。
		if d.maxPorts > 0 {
			if total := len(dev.v4.m) + len(dev.v6.m); total > d.maxPorts {
				d.portEvictions += int64(dev.evictPorts(nowNano, windowNano, total-d.maxPorts))
			}
		}
		if len(dev.v4.m) == 0 && len(dev.v6.m) == 0 {
			delete(d.devices, mac)
		}
	}
	// 设备 map 明显缩小时重建（如大量设备下线后仅剩少数）。
	if newDevices, ok := compactMap(d.devices, d.devicesPeak); ok {
		d.devices = newDevices
		d.devicesPeak = len(newDevices)
	}
}

// scan 清理该地址族端口表内的超时对端、检查告警，并回收明显缩水的 map。
// 两张表（IPv4 / IPv6）共用这一份泛型实现，仅对端键类型不同。
func (t *portsTable[K]) scan(d *Detector, mac netutil.MAC, v6 bool, now time.Time, nowNano, windowNano int64) {
	if len(t.m) > t.peak {
		t.peak = len(t.m)
	}
	for key, ps := range t.m {
		ps.peers.recordPeak()
		ps.peers.evict(nowNano, windowNano)

		checkPort(d, mac, key, ps, v6, now)

		// 持续期内即使窗口内对端全部过期也保留端口状态，以便后续新对端继续判定。
		if ps.peers.count() == 0 && ps.alertStartNano == 0 {
			delete(t.m, key)
		} else {
			ps.peers.compact()
		}
	}
	// 端口 map 明显缩小时重建（如设备大量端口关闭后仅剩少数）。
	if nm, ok := compactMap(t.m, t.peak); ok {
		t.m = nm
		t.peak = len(nm)
	}
}

// Counts 返回跟踪设备数与累计告警数（轻量，供 HTTP API /status 使用）。
func (d *Detector) Counts() (devices, alerts int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.devices), d.alerts
}

// Summary 输出汇总信息。
func (d *Detector) Summary() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logger.Printf("统计：当前跟踪设备 %d 个，累计告警 %d 次；端口上限提前过期 %d 个端口、丢弃 %d 个新端口报文",
		len(d.devices), d.alerts, d.portEvictions, d.portDrops)
}
