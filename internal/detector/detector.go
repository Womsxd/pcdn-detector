// Package detector 维护滑动窗口内的连接统计，并在超过阈值时告警。
package detector

import (
	"container/heap"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/state"
	"pcdn-detect/internal/util"
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

// 端口上限（[memory] max_ports）相关参数。
const (
	// portsEvictPercent：端口数达到上限时一次性提前过期的比例（百分比）。
	// 批量淘汰用于摊薄「全表排序选候选」的开销：只在每新增约 10% 端口时做一次排序，
	// 平均到每个新端口是 O(log n)，避免每个新端口都全表排序被攻击者当成 CPU 放大器。
	portsEvictPercent = 10

	// expiryBuckets：把「距过期窗口的剩余寿命」按窗口均分成的档数。
	// 淘汰先按档位（越接近过期越优先），同档内再按对端数升序。之所以要分档：端口时间戳是
	// 纳秒级的，严格按时间排序时「对端数」几乎永远不参与比较；分档后两个条件才都真正生效。
	expiryBuckets = 10

	// dropLogEvery：因端口上限丢弃新端口报文时，日志按丢弃次数限频（首次 + 每 N 次），
	// 避免被扫描流量刷屏（日志本身也是可被放大的资源）。
	dropLogEvery = 100000
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

// peerKey4 / peerKey6 是远端对端的键：分别用 4 字节（IPv4）与 16 字节（IPv6）的
// 紧凑地址表示。由于端口表已按地址族拆分（device.v4 / device.v6），每个端口只会用到其中
// 一种键类型，故可按地址族选用最紧凑的表示：纯 IPv4 场景下每个键仅 4 字节，比统一用
// As16() 的 16 字节省 12 字节（内联数组与 map bucket 都按值存放键，对端越多收益越大）。
//
// netip.Addr 本身为 24 字节（16 字节地址 + 8 字节的“地址种类”哨兵指针 z），而同一个
// 对端集合内的地址族必然一致，该区分位完全冗余。
type peerKey4 [4]byte
type peerKey6 [16]byte

// addr 把 4 字节键还原为纯 IPv4 地址，仅用于低频的日志格式化。
func (k peerKey4) addr() netip.Addr { return netip.AddrFrom4([4]byte(k)) }

// addr 把 16 字节键还原为 netip.Addr，仅用于低频的日志格式化。
// 对端若为 IPv4，其 As16() 会得到 IPv4-mapped 形式（::ffff:a.b.c.d），
// 需 Unmap() 还原为纯 IPv4，否则字符串化后会输出带 ::ffff: 前缀的地址。
func (k peerKey6) addr() netip.Addr { return netip.AddrFrom16([16]byte(k)).Unmap() }

// peerKey 是对端键的公共约束：可用作 map 键，并能还原为 netip.Addr（仅低频的日志格式化 /
// 快照输出使用）。有了它，对端集合及各端口操作（清理过期、标记已提示、收集新增 IP 等）
// 只需按地址族实例化一份泛型代码，不再维护 peers4 / peers6 两套成对的重复实现。
type peerKey interface {
	comparable
	addr() netip.Addr
}

// peer 表示一个远端对端。
//
// 仅保留滑动窗口判定所需的最小字段：远端地址以地址族对应的紧凑键（peerKey4 / peerKey6）
// 作为对端集合的键承载，故此处不再冗余保存 IP 字符串，也不再为每个对端维护端口集合。
//
// 上行 / 下行字节数只在**端口级**（portStat.upBytes / downBytes）累计：对端级字节数
// 从未被任何告警或统计读取，属于纯冗余字段。去掉后 peer 由 32 字节缩到 16 字节，实测每记录
// 一个对端约省 35 字节（约 44%）；对端数量越大收益越大（详见 README 量化参考）。
//
// lastSeenNano 用 int64（Unix 纳秒）而非 time.Time 保存时间：时间戳本就直接来自
// 抓包层的内核时间（无单调时钟），改为定长整数后每个对端省下 16 字节，且比较等价。
//
// reported 复用 peer 自身承载「本轮是否已提示」标记，从而不再为每个端口额外维护
// 一份与 peers 同规模的 reported 集合：既省下几乎一半的对端内存，也避免长期告警时
// 该集合只增不减导致内存持续增长。
type peer struct {
	lastSeenNano int64
	reported     bool
}

// inlinePeers 是单端口内联保存的对端数量上限。
//
// 绝大多数端口只有 1 个对端（客户端式临时端口），若一律分配 map，每个端口都要额外付出一份
// hmap + bucket 的固定开销（约 200 字节）。故不超过 inlinePeers 个对端时直接存在端口结构体内
// 的定长数组里（零额外分配），超过后再升级为 map：单对端端口的占用由约 366 字节降到约 144
// 字节（portStat 恰好落在 Go 的 144 字节分配档）。
const inlinePeers = 4

// alertLogMaxIPs 是单条告警日志最多列出的对端 IP 数。peer_limit = 0 时单个端口可能有数万对端，
// 全量格式化会刷屏（logd / 串口）并瞬时占用大量内存。日志只列前 N 个，并注明真实总数。
const alertLogMaxIPs = 20

// peerEntry 是内联存储的对端项。
//
// 字段顺序按对齐放置（键 → 是否已提示 → 时间戳）：bool 填进键与 int64 之间的填充位，
// 使 IPv4 场景每项仅 16 字节（若把 bool 放在 int64 之后，整项会被填充到 24 字节）。
type peerEntry[K peerKey] struct {
	key          K
	reported     bool
	lastSeenNano int64
}

// peerSet 是单个端口的对端集合。
//
// 元素数 ≤ inlinePeers 时线性存放在 small 中（顺序无意义，删除用「与末位交换」），超过后升级
// 到 large。集合容量很小时，线性查找 / 遍历比 map 更快也更省内存。
//
// 一旦升级为 map 就不再退回内联：端口空闲（对端全部过期且未告警）时整个端口状态会被删除，
// map 随之一并释放；在此之前保留 map，避免对端数围绕 inlinePeers 抖动时反复升级 / 降级。
//
// peak 为元素数峰值，用于判断 map 是否需要重建以回收 bucket。
type peerSet[K peerKey] struct {
	small [inlinePeers]peerEntry[K]
	large map[K]peer
	n     int
	peak  int
}

// portStat 表示某设备上一个“本地端口 + 传输层协议”的对端集合。
//
// 端口号 / 传输层协议与所属端口表的键（portKey）逐字段重复，地址族则由所在表
// （device.v4 / device.v6）决定，故均不再冗余保存：调用方（Observe 与 Scan 遍历）始终持有
// portKey，把它传给需要的方法即可；需要格式化设备 IP 时再由调用方传入地址族。
type portStat[K peerKey] struct {
	peers          peerSet[K] // 对端集合：少量对端内联存放，不超过 inlinePeers 时不分配 map
	ipRaw          [16]byte   // 该端口设备本地 IP 的紧凑表示（地址族由所属端口表区分，格式化见 deviceIP）
	upBytes        uint64
	downBytes      uint64
	lastActiveNano int64 // 该端口最近一次收到任一报文的时间（Unix 纳秒）；持续期据此按“仍有流量”续期
	// alertStartNano 为本轮最近一次告警续期时间（Unix 纳秒）；0 表示未处于告警中。
	// 与 lastActiveNano 用同样的 int64 纳秒表示（而非 24 字节的 time.Time），每个端口省 16 字节。
	alertStartNano int64
	reportedCount  int // 本轮累计去重后已提示的对端数；是否已提示记录在各 peer.reported
}

// portKey 以「端口 + 传输层协议」为键；地址族由所属端口表（device.v4 / device.v6）区分：
//   - 同一 MAC 可能同时拥有 IPv4 与 IPv6 地址，必须按地址族分开统计，否则设备 IP 会被
//     另一地址族的流量覆盖，导致输出错乱；
//   - 同一端口上的 UDP 与 TCP 也分开统计，使告警能携带触发协议，
//     从而「UDP 触发只封 UDP、TCP 触发只封 TCP」。
type portKey struct {
	port  uint16
	proto uint8
}

// device 表示一个被跟踪的设备（以 MAC 标识），持有按地址族拆分的两张端口表。
//
// MAC 即 devices 的键，无需在 device 内重复保存：告警日志 / 回调所需的 MAC 由 Scan 遍历
// devices 时取得的 key 提供。按地址族拆表（而不是在端口键里放 v6 标志）是单对端端口免分配
// map 的前提：每张表的端口结构都能按自己的键宽内联保存少量对端（见 peerSet），
// 纯 IPv4 场景每项仅 16 字节。
type device struct {
	v4 portsTable[peerKey4]
	v6 portsTable[peerKey6]
}

// portsTable 是某地址族下的端口表（端口键 → 端口状态）。
type portsTable[K peerKey] struct {
	m    map[portKey]*portStat[K]
	peak int // m 的元素数峰值，用于在明显缩小时重建该 map 以回收内存
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

// portFor 取出某端口的状态；不存在时先确保该设备还有端口配额，再创建。
// 返回 nil 表示已到上限且没有可提前过期的端口（调用方应丢弃该新端口的报文）。
func portFor[K peerKey](d *Detector, dev *device, t *portsTable[K], key portKey, nowNano int64) *portStat[K] {
	if ps := t.m[key]; ps != nil {
		return ps
	}
	if !d.makePortRoom(dev, nowNano) {
		return nil
	}
	if t.m == nil {
		t.m = make(map[portKey]*portStat[K])
	}
	ps := &portStat[K]{}
	t.m[key] = ps
	return ps
}

// port 取出某端口的状态，不存在则创建。仅供启动时还原告警会话使用（绕过端口上限：
// 还原的端口都处于告警中，本就不会被提前过期）。
func (t *portsTable[K]) port(key portKey) *portStat[K] {
	ps := t.m[key]
	if ps == nil {
		if t.m == nil {
			t.m = make(map[portKey]*portStat[K])
		}
		ps = &portStat[K]{}
		t.m[key] = ps
	}
	return ps
}

// makePortRoom 在设备端口数达到上限时批量提前过期一部分端口，为新端口腾出位置。
// 返回 false 表示已无端口可淘汰（全部处于告警中），调用方应丢弃该新端口的报文。
func (d *Detector) makePortRoom(dev *device, nowNano int64) bool {
	if d.maxPorts <= 0 {
		return true // 未启用上限
	}
	total := len(dev.v4.m) + len(dev.v6.m)
	if total < d.maxPorts {
		return true
	}
	quota := total * portsEvictPercent / 100
	if quota < 1 {
		quota = 1
	}
	n := dev.evictPorts(nowNano, int64(d.window), quota)
	d.portEvictions += int64(n)
	return n > 0
}

// dropNewPort 记录因端口上限丢弃的新端口报文：该端口没有 portStat，字节数无处累计。
// 日志按丢弃次数限频（首次 + 每 dropLogEvery 次），避免被扫描流量刷屏。
func (d *Detector) dropNewPort(o Observation) {
	d.portDrops++
	if d.portDrops != 1 && d.portDrops%dropLogEvery != 0 {
		return
	}
	d.logger.Printf("%s(%s) 的端口 %d(%s) 因端口条目达到上限（每设备 %d 个）且无端口可提前过期被丢弃（累计丢弃 %d 个报文）",
		util.MaskDeviceMAC(d.hide, o.MAC.String()), util.MaskDeviceIP(d.hide, o.IP.String()), o.LocalPort,
		protoName(o.Proto), d.maxPorts, d.portDrops)
}

// portCandidate 是提前过期的候选端口。只保留排序与删除所需的字段：两张端口表的 portStat
// 泛型类型不同，无法放进同一个切片，故键按 portKey + 地址族擦除。
type portCandidate struct {
	key        portKey
	v6         bool
	bucket     int   // 剩余寿命档位：0 = 最接近过期
	peers      int   // 当前对端数
	lastActive int64 // 最近活动时间（Unix 纳秒）
}

// evictPorts 提前过期最多 quota 个端口，返回实际过期数。
// 排序：先按剩余寿命档位升序（越接近过期越优先），同档内按对端数升序（越少越优先），
// 再按最近活动时间、端口号升序保证确定性；处于告警中的端口不参与淘汰（否则会打断续期、
// 结束回调与解封）。
func (dev *device) evictPorts(nowNano, windowNano int64, quota int) int {
	if quota <= 0 {
		return 0
	}
	cands := make([]portCandidate, 0, len(dev.v4.m)+len(dev.v6.m))
	cands = appendPortCandidates(cands, &dev.v4, false, nowNano, windowNano)
	cands = appendPortCandidates(cands, &dev.v6, true, nowNano, windowNano)
	if len(cands) == 0 {
		return 0
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.bucket != b.bucket {
			return a.bucket < b.bucket
		}
		if a.peers != b.peers {
			return a.peers < b.peers
		}
		if a.lastActive != b.lastActive {
			return a.lastActive < b.lastActive
		}
		if a.key.port != b.key.port {
			return a.key.port < b.key.port
		}
		if a.key.proto != b.key.proto {
			return a.key.proto < b.key.proto
		}
		return !a.v6 && b.v6
	})
	if quota > len(cands) {
		quota = len(cands)
	}
	for i := 0; i < quota; i++ {
		if c := cands[i]; c.v6 {
			delete(dev.v6.m, c.key)
		} else {
			delete(dev.v4.m, c.key)
		}
	}
	return quota
}

// appendPortCandidates 收集某地址族端口表中可提前过期的端口（跳过告警中的）。
func appendPortCandidates[K peerKey](dst []portCandidate, t *portsTable[K], v6 bool, nowNano, windowNano int64) []portCandidate {
	for key, ps := range t.m {
		if ps.alertStartNano != 0 {
			continue
		}
		dst = append(dst, portCandidate{
			key:        key,
			v6:         v6,
			bucket:     expiryBucket(nowNano, ps.lastActiveNano, windowNano),
			peers:      ps.peers.count(),
			lastActive: ps.lastActiveNano,
		})
	}
	return dst
}

// expiryBucket 把「距过期窗口的剩余寿命」按窗口均分为 expiryBuckets 档：
// 0 = 剩余不足 1/expiryBuckets 窗口（最接近过期），expiryBuckets-1 = 最“新鲜”。
// 已过期（剩余 <= 0）的端口同样归入 0 档，由 Scan 正常清理。
func expiryBucket(nowNano, lastActiveNano, windowNano int64) int {
	if windowNano <= 0 {
		return 0
	}
	remaining := windowNano - (nowNano - lastActiveNano)
	if remaining <= 0 {
		return 0
	}
	b := int(remaining * expiryBuckets / windowNano)
	if b >= expiryBuckets {
		b = expiryBuckets - 1
	}
	return b
}

// observe 记录一条属于该端口的观测：刷新设备 IP 与端口活动时间、累计端口级流量，
// 并刷新对端记录（低内存模式告警期间只累计流量，不再记录对端）。
//
// k 为该报文远端对端的键；limit 为对端记录上限（0 表示不限制）：已达上限时不再新增对端，
// 但本次流量仍完整计入端口级累计，已有对端不受影响（照常刷新）。
func (ps *portStat[K]) observe(k K, o Observation, limit int, lowMemory bool) {
	ps.setIP(o.IP, o.V6)

	// 记录端口最近活动时间：持续期内只要仍有流量即可续期（不区分对端新旧）。
	ps.lastActiveNano = o.TS.UnixNano()

	// 低内存模式：该端口一旦触发告警（alertStartNano 非零），清空后即不再记录新对端 IP，
	// 仅保留触发状态并累计端口级流量（定长字段，不随对端数量增长）。
	if lowMemory && ps.alertStartNano != 0 {
		ps.addBytes(o)
		return
	}

	// 对端以值存储：读取-更新-写回，避免为每个新对端分配 *peer。
	p, exists := ps.peers.get(k)
	if !exists && limit > 0 && ps.peers.count() >= limit {
		ps.addBytes(o)
		return
	}
	p.lastSeenNano = o.TS.UnixNano()
	ps.peers.put(k, p)
	ps.addBytes(o)
}

// addBytes 把本次报文字节数计入端口级累计（对端级不再保存字节数，见 peer 说明）。
func (ps *portStat[K]) addBytes(o Observation) {
	if o.Up {
		ps.upBytes += uint64(o.Length)
		return
	}
	ps.downBytes += uint64(o.Length)
}

// count 返回对端数量。
func (s *peerSet[K]) count() int {
	if s.large != nil {
		return len(s.large)
	}
	return s.n
}

// get 返回某个对端的状态；不存在时 ok 为 false。
func (s *peerSet[K]) get(k K) (peer, bool) {
	if s.large != nil {
		p, ok := s.large[k]
		return p, ok
	}
	for i := 0; i < s.n; i++ {
		if s.small[i].key == k {
			return peer{lastSeenNano: s.small[i].lastSeenNano, reported: s.small[i].reported}, true
		}
	}
	return peer{}, false
}

// put 写入（新增或更新）一个对端；内联槽位已满时先把已有对端整体迁入 map。
func (s *peerSet[K]) put(k K, p peer) {
	if s.large != nil {
		s.large[k] = p
		return
	}
	for i := 0; i < s.n; i++ {
		if s.small[i].key == k {
			s.small[i].lastSeenNano = p.lastSeenNano
			s.small[i].reported = p.reported
			return
		}
	}
	if s.n == inlinePeers {
		s.upgrade()
		s.large[k] = p
		return
	}
	s.small[s.n] = peerEntry[K]{key: k, reported: p.reported, lastSeenNano: p.lastSeenNano}
	s.n++
}

// evict 删除窗口外的对端。
func (s *peerSet[K]) evict(nowNano, windowNano int64) {
	if s.large != nil {
		for k, p := range s.large {
			if nowNano-p.lastSeenNano > windowNano {
				delete(s.large, k)
			}
		}
		return
	}
	for i := 0; i < s.n; {
		if nowNano-s.small[i].lastSeenNano > windowNano {
			// 与末位交换后删除（集合顺序无意义）：常数时间，且不留空槽。
			s.n--
			s.small[i] = s.small[s.n]
			s.small[s.n] = peerEntry[K]{}
			continue
		}
		i++
	}
}

// clear 释放该端口的全部对端记录（低内存模式触发告警后调用）：内联槽位清空、map 置 nil
// 使底层 bucket 数组可被 GC 回收；触发状态（reportedCount / alertStartNano 等）保留。
func (s *peerSet[K]) clear() {
	s.small = [inlinePeers]peerEntry[K]{}
	s.large = nil
	s.n = 0
	s.peak = 0
}

// markAllReported 把窗口内全部对端标记为本轮已提示，并返回当前对端数。
// 复用对端自身的标记，无需再分配一份与对端集合同规模的集合。
func (s *peerSet[K]) markAllReported() int {
	if s.large != nil {
		for k, p := range s.large {
			p.reported = true
			s.large[k] = p
		}
		return len(s.large)
	}
	for i := 0; i < s.n; i++ {
		s.small[i].reported = true
	}
	return s.n
}

// clearReported 结束本轮：清除全部已提示标记，供下一轮重新统计。
func (s *peerSet[K]) clearReported() {
	if s.large != nil {
		for k, p := range s.large {
			if p.reported {
				p.reported = false
				s.large[k] = p
			}
		}
		return
	}
	for i := 0; i < s.n; i++ {
		s.small[i].reported = false
	}
}

// collectNewReported 标记并返回本轮新出现的对端键（持续期用），仅在告警时调用。
// 返回键而非 IP 字符串：新增数量由调用方累加到 reportedCount，只有实际要展示的前 N 个才需格式化。
func (s *peerSet[K]) collectNewReported() []K {
	var keys []K
	if s.large != nil {
		for k, p := range s.large {
			if !p.reported {
				p.reported = true
				s.large[k] = p
				keys = append(keys, k)
			}
		}
		return keys
	}
	for i := 0; i < s.n; i++ {
		if !s.small[i].reported {
			s.small[i].reported = true
			keys = append(keys, s.small[i].key)
		}
	}
	return keys
}

// keys 返回全部对端键的副本。键是紧凑数组（4 / 16 字节），复制远比格式化 IP 字符串便宜。
func (s *peerSet[K]) keys() []K {
	keys := make([]K, 0, s.count())
	if s.large != nil {
		for k := range s.large {
			keys = append(keys, k)
		}
		return keys
	}
	for i := 0; i < s.n; i++ {
		keys = append(keys, s.small[i].key)
	}
	return keys
}

// headIPs 返回按地址数值序排序的前 limit 个对端 IP（limit <= 0 表示不限制），以及真实对端总数。
// 只格式化被展示的对端：peer_limit = 0 时单端口可能有数万对端，全量格式化会在持锁状态下
// 产生大量临时字符串，并把日志 / 响应撑得过大。
func (s *peerSet[K]) headIPs(limit int) ([]string, int) {
	return formatIPs(s.keys(), limit)
}

// formatIPs 把对端键格式化为 IP 字符串（按地址数值序），limit > 0 时只保留前 limit 个。
// 返回格式化结果与传入的键总数（调用方据此展示「共 N 个」）。
func formatIPs[K peerKey](keys []K, limit int) ([]string, int) {
	total := len(keys)
	if limit > 0 && total > limit {
		keys = topNKeys(keys, limit)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].addr().Compare(keys[j].addr()) < 0 })
	ips := make([]string, len(keys))
	for i, k := range keys {
		ips[i] = k.addr().String()
	}
	return ips, total
}

// topNKeys 用容量为 n 的最大堆筛出 keys 中地址最小的 n 个键，不修改入参，也不格式化任何地址。
// 相比完整排序只需 O(len(keys)·log n) 次比较，对「只想要前 N 个」的场景更划算。
func topNKeys[K peerKey](keys []K, n int) []K {
	if n <= 0 || n >= len(keys) {
		return keys
	}
	h := make(maxAddrHeap[K], 0, n)
	for _, k := range keys {
		if h.Len() < n {
			heap.Push(&h, k)
			continue
		}
		if k.addr().Compare(h[0].addr()) < 0 {
			h[0] = k
			heap.Fix(&h, 0)
		}
	}
	return h
}

// maxAddrHeap 是按地址数值序的大顶堆（堆顶为当前最大的键），用于筛出最小的 n 个。
type maxAddrHeap[K peerKey] []K

func (h maxAddrHeap[K]) Len() int { return len(h) }
func (h maxAddrHeap[K]) Less(i, j int) bool {
	return h[i].addr().Compare(h[j].addr()) > 0
}
func (h maxAddrHeap[K]) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *maxAddrHeap[K]) Push(x any)   { *h = append(*h, x.(K)) }
func (h *maxAddrHeap[K]) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// recordPeak 记录当前对端数作为峰值（仅在 Scan 清理之前调用，此时长度即上一区间峰值）。
func (s *peerSet[K]) recordPeak() {
	if n := s.count(); n > s.peak {
		s.peak = n
	}
}

// compact 在对端集合明显缩小时重建 map，回收删除对端后不再释放的 bucket 内存。
// 内联状态没有可回收的 bucket，只把峰值收敛为当前值。
//
// 一旦升级为 map 就不再退回内联：端口出现过 inlinePeers 个以上对端后，通常还会继续出现
// 新对端，保留已有 map 可避免「对端数围绕 inlinePeers 抖动时反复升级 / 降级」；端口彻底
// 空闲后由 Scan 删除整个端口状态（见 portsTable.scan），map 随之一并释放。
func (s *peerSet[K]) compact() {
	if s.large == nil {
		s.peak = s.n
		return
	}
	if nm, ok := compactMap(s.large, s.peak); ok {
		s.large = nm
		s.peak = len(nm)
	}
}

// upgrade 把内联保存的对端整体迁入 map（内联槽位已满时调用）。
func (s *peerSet[K]) upgrade() {
	m := make(map[K]peer, 2*inlinePeers)
	for i := 0; i < s.n; i++ {
		m[s.small[i].key] = peer{lastSeenNano: s.small[i].lastSeenNano, reported: s.small[i].reported}
	}
	s.large = m
	s.small = [inlinePeers]peerEntry[K]{}
	s.n = 0
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

// checkPort 根据端口当前情况判定并输出告警。
// 首次达到阈值输出「疑似产生PCDN行为」；随后进入持续期：
//   - 只要该端口仍有流量（任意对端，无论新旧），就按最近活动时间刷新计时器；
//   - 期间出现新的对端 IP（哪怕只有 1 个）时额外输出「持续产生PCDN行为」；
//
// 持续期不再要求窗口内对端数达到阈值；若持续 alertDuration 内都没有任何流量，
// 则输出「PCDN行为结束」并结束本轮，之后可重新触发。
//
// mac / key 为该端口所属设备与端口的 map 键；v6 为该端口所属的地址族（决定设备 IP 的格式化
// 方式）。设备 MAC、端口号、协议、地址族均由此取得，无需在 device / portStat 内重复保存。
func checkPort[K peerKey](d *Detector, mac netutil.MAC, key portKey, ps *portStat[K], v6 bool, now time.Time) {
	proto := protoName(key.proto)
	if ps.alertStartNano == 0 {
		// 未处于告警中：窗口内对端数达到阈值才触发。
		if ps.peers.count() < d.threshold {
			return
		}
		ps.alertStartNano = now.UnixNano()
		// 只格式化要展示的前 N 个：peer_limit = 0 时对端可能有数万，全量格式化会刷屏。
		ips, totalPeers := ps.peers.headIPs(alertLogMaxIPs)
		d.alerts++
		d.logger.Printf("%s(%s) 的端口 %d(%s) 疑似产生PCDN行为（近 %s 内 %d 个对端IP，累计上行 %s / 下行 %s），相关IP为%s: %s",
			util.MaskDeviceMAC(d.hide, mac.String()), util.MaskDeviceIP(d.hide, ps.deviceIP(v6).String()), key.port, proto, d.window, totalPeers, util.HumanBytes(ps.upBytes), util.HumanBytes(ps.downBytes), truncatedNote(totalPeers, len(ips)), strings.Join(ips, ", "))
		if d.sink != nil {
			d.sink.OnAlertStart(mac.String(), ps.deviceIP(v6).String(), key.port, proto)
		}
		if d.lowMemory {
			// 低内存模式：清空对端列表并停止记录新对端，仅保留触发状态与累计计数。
			ps.reportedCount = totalPeers
			ps.peers.clear()
		} else {
			// 本轮初始已提示集合 = 当前窗口内全部对端（标记复用 peer.reported，零额外分配）。
			ps.reportedCount = ps.peers.markAllReported()
		}
		return
	}

	// 持续期内只要仍有流量，就按最近活动时间续期：避免对端流量仍在持续时，
	// 仅因没有新对端 IP 而被误判为「PCDN行为结束」。
	if ps.lastActiveNano > ps.alertStartNano {
		ps.alertStartNano = ps.lastActiveNano
	}

	// 持续期内长时间没有任何流量：本轮结束，允许后续重新触发。
	if now.UnixNano()-ps.alertStartNano > int64(d.alertDuration) {
		d.logger.Printf("%s(%s) 的端口 %d(%s) PCDN行为结束（本轮累计 %d 个对端IP，累计上行 %s / 下行 %s）",
			util.MaskDeviceMAC(d.hide, mac.String()), util.MaskDeviceIP(d.hide, ps.deviceIP(v6).String()), key.port, proto, ps.reportedCount, util.HumanBytes(ps.upBytes), util.HumanBytes(ps.downBytes))
		if d.sink != nil {
			d.sink.OnAlertEnd(mac.String(), ps.deviceIP(v6).String(), key.port, proto)
		}
		ps.alertStartNano = 0
		ps.peers.clearReported()
		ps.reportedCount = 0
		return
	}

	// 期间出现新对端 IP 时额外输出「持续产生PCDN行为」（计时器已由流量续期）。
	// 仅在真正需要展示时才把 netip.Addr 转成字符串，且只格式化前 N 个。
	newKeys := ps.peers.collectNewReported()
	if len(newKeys) == 0 {
		return
	}
	ps.reportedCount += len(newKeys)
	newIPs, _ := formatIPs(newKeys, alertLogMaxIPs)
	d.alerts++
	d.logger.Printf("%s(%s) 的端口 %d(%s) 持续产生PCDN行为（本轮累计 %d 个对端IP，累计上行 %s / 下行 %s），新增相关IP为%s: %s",
		util.MaskDeviceMAC(d.hide, mac.String()), util.MaskDeviceIP(d.hide, ps.deviceIP(v6).String()), key.port, proto, ps.reportedCount, util.HumanBytes(ps.upBytes), util.HumanBytes(ps.downBytes), truncatedNote(len(newKeys), len(newIPs)), strings.Join(newIPs, ", "))
}

// truncatedNote 返回日志中「IP 列表被截断」的说明，未截断时为空。
func truncatedNote(total, shown int) string {
	if total <= shown {
		return ""
	}
	return fmt.Sprintf("（共 %d 个，仅列前 %d 个）", total, shown)
}

// setIP 记录该端口的设备本地 IP：按地址族（v6）紧凑保存到 ipRaw，省去 netip.Addr 中用于
// 区分地址族 / zone 的冗余哨兵指针（每个端口省 8 字节，32 位平台省 4 字节）。无效地址忽略
// （保留原值），与原先「仅在有效时更新」的行为一致。
func (ps *portStat[K]) setIP(ip netip.Addr, v6 bool) {
	if !ip.IsValid() {
		return
	}
	if v6 {
		ps.ipRaw = ip.As16()
		return
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return
	}
	ps.ipRaw = [16]byte{}
	a := ip.As4()
	copy(ps.ipRaw[:4], a[:])
}

// deviceIP 把 ipRaw 还原为设备本地 IP，仅用于低频的日志 / 回调格式化。
func (ps *portStat[K]) deviceIP(v6 bool) netip.Addr {
	if v6 {
		return netip.AddrFrom16(ps.ipRaw)
	}
	return netip.AddrFrom4([4]byte(ps.ipRaw[:4]))
}

// restore 还原一个告警会话的触发状态（启动时恢复用）。
func (ps *portStat[K]) restore(s state.AlertSession) {
	ps.setIP(s.IP, s.V6)
	ps.alertStartNano = s.AlertStartNano
	ps.lastActiveNano = s.LastActiveNano
	ps.reportedCount = s.ReportedCount
}

// Snapshot 是检测器当前状态的只读快照（供 HTTP API 使用）。
type Snapshot struct {
	TrackedDevices int          `json:"tracked_devices"`
	Alerts         int          `json:"alerts"`
	PortEvictions  int64        `json:"port_evictions"` // 累计因端口上限提前过期的端口条目数
	PortDrops      int64        `json:"port_drops"`     // 累计因端口上限丢弃的新端口报文数
	Devices        []DeviceView `json:"devices"`
}

// DeviceView 是单个设备的快照。
type DeviceView struct {
	MAC   string     `json:"mac"`
	Ports []PortView `json:"ports"`
}

// PortView 是单个「端口 + 协议 + 地址族」的统计快照。
// 对端 IP 列表不在汇总快照中返回，需按需通过 Peers 查询（见 PeerView）。
type PortView struct {
	Port      uint16 `json:"port"`
	Proto     string `json:"proto"`
	V6        bool   `json:"v6"`
	PeerCount int    `json:"peer_count"`
	UpBytes   uint64 `json:"up_bytes"`
	DownBytes uint64 `json:"down_bytes"`
	Alerting  bool   `json:"alerting"`
}

// PeerView 是单个「端口 + 协议 + 地址族」的对端 IP 列表快照，按需查询以降低汇总接口压力。
type PeerView struct {
	Port      uint16   `json:"port"`
	Proto     string   `json:"proto"`
	V6        bool     `json:"v6"`
	PeerCount int      `json:"peer_count"` // 该端口真实对端数（不受 limit 影响）
	PeerIPs   []string `json:"peer_ips"`
	Truncated bool     `json:"truncated"` // 对端 IP 列表是否因上限被截断
}

// Snapshot 返回检测器当前状态的快照（仅统计信息，不含对端 IP 列表）。
func (d *Detector) Snapshot() Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := Snapshot{TrackedDevices: len(d.devices), Alerts: d.alerts, PortEvictions: d.portEvictions, PortDrops: d.portDrops}
	if len(d.devices) == 0 {
		return out
	}

	macs := make([]netutil.MAC, 0, len(d.devices))
	for mac := range d.devices {
		macs = append(macs, mac)
	}
	sort.Slice(macs, func(i, j int) bool { return macs[i].String() < macs[j].String() })

	for _, mac := range macs {
		dev := d.devices[mac]
		dv := DeviceView{MAC: mac.String()}
		dv.Ports = appendPortViews(dv.Ports, &dev.v4, false)
		dv.Ports = appendPortViews(dv.Ports, &dev.v6, true)
		// 两张表分别已按「端口 → 协议」排好序，合并后按「端口 → 协议 → 地址族」再排一次
		// （IPv4 在前），保持与按地址族分表之前一致的输出顺序。
		sort.Slice(dv.Ports, func(i, j int) bool {
			a, b := dv.Ports[i], dv.Ports[j]
			if a.Port != b.Port {
				return a.Port < b.Port
			}
			if a.Proto != b.Proto {
				return a.Proto < b.Proto
			}
			return !a.V6 && b.V6
		})
		out.Devices = append(out.Devices, dv)
	}
	return out
}

// appendPortViews 把某地址族端口表的内容按「端口 → 协议」顺序追加为快照视图。
func appendPortViews[K peerKey](dst []PortView, t *portsTable[K], v6 bool) []PortView {
	keys := make([]portKey, 0, len(t.m))
	for k := range t.m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})
	for _, key := range keys {
		ps := t.m[key]
		dst = append(dst, PortView{
			Port:      key.port,
			Proto:     protoName(key.proto),
			V6:        v6,
			PeerCount: ps.peers.count(),
			UpBytes:   ps.upBytes,
			DownBytes: ps.downBytes,
			Alerting:  ps.alertStartNano != 0,
		})
	}
	return dst
}

// Peers 返回某「设备 + 本地端口 + 协议 + 地址族」的对端 IP 列表（按地址数值序）。
// limit 为最多返回的 IP 数（<=0 表示不限制），超出时截断并置 Truncated；PeerCount 始终为真实对端数。
// ok 为 false 表示该设备 / 端口未被跟踪。
//
// 锁内只复制对端键（每个 4 / 16 字节），排序、筛选 Top-N 与字符串格式化都在锁外完成：
// limit 的语义是「只想要前 N 个」，不应让抓包与扫描线程为全部对端的格式化买单。
func (d *Detector) Peers(mac netutil.MAC, port uint16, proto uint8, v6 bool, limit int) (PeerView, bool) {
	key := portKey{port: port, proto: proto}

	d.mu.Lock()
	dev, ok := d.devices[mac]
	if !ok {
		d.mu.Unlock()
		return PeerView{}, false
	}
	var (
		keys4 []peerKey4
		keys6 []peerKey6
	)
	if v6 {
		keys6, ok = peerKeysOf(&dev.v6, key)
	} else {
		keys4, ok = peerKeysOf(&dev.v4, key)
	}
	d.mu.Unlock()
	if !ok {
		return PeerView{}, false
	}
	if v6 {
		return peerView(keys6, key, true, limit), true
	}
	return peerView(keys4, key, false, limit), true
}

// peerKeysOf 在锁内取出某端口的对端键副本。返回 false 表示该端口未被跟踪。
func peerKeysOf[K peerKey](t *portsTable[K], key portKey) ([]K, bool) {
	ps, ok := t.m[key]
	if !ok {
		return nil, false
	}
	return ps.peers.keys(), true
}

// peerView 由对端键副本构造视图（在锁外调用，避免持锁排序 / 格式化）。
func peerView[K peerKey](keys []K, key portKey, v6 bool, limit int) PeerView {
	ips, total := formatIPs(keys, limit)
	return PeerView{
		Port:      key.port,
		Proto:     protoName(key.proto),
		V6:        v6,
		PeerCount: total,
		PeerIPs:   ips,
		Truncated: limit > 0 && total > limit,
	}
}

// Counts 返回跟踪设备数与累计告警数（轻量，供 HTTP API /status 使用）。
func (d *Detector) Counts() (devices, alerts int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.devices), d.alerts
}

// SetFilter 热替换名单过滤器（供 reload 热应用 [filter] 变更）。
// 仅替换指针且与 Observe 的无锁读通过原子指针同步，不影响检测状态本身。
func (d *Detector) SetFilter(f *filter.DeviceFilter) {
	d.filter.Store(f)
}

// AlertSessions 导出当前处于告警中的端口会话（供 reload 重启继承）。
func (d *Detector) AlertSessions() []state.AlertSession {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []state.AlertSession
	for mac, dev := range d.devices {
		out = appendAlertSessions(out, mac, &dev.v4, false)
		out = appendAlertSessions(out, mac, &dev.v6, true)
	}
	return out
}

// appendAlertSessions 追加某地址族端口表中处于告警中的会话。
func appendAlertSessions[K peerKey](dst []state.AlertSession, mac netutil.MAC, t *portsTable[K], v6 bool) []state.AlertSession {
	for key, ps := range t.m {
		if ps.alertStartNano == 0 {
			continue
		}
		dst = append(dst, state.AlertSession{
			MAC:            mac,
			Port:           key.port,
			Proto:          key.proto,
			V6:             v6,
			IP:             ps.deviceIP(v6),
			AlertStartNano: ps.alertStartNano,
			LastActiveNano: ps.lastActiveNano,
			ReportedCount:  ps.reportedCount,
		})
	}
	return dst
}

// RestoreSessions 还原告警会话（启动时执行）：重建对应端口状态并置回告警起止时间，
// 使后续 Scan 能像重启前一样按流量续期、并在超时后正常触发「PCDN行为结束」回调。
func (d *Detector) RestoreSessions(sessions []state.AlertSession) {
	if len(sessions) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, s := range sessions {
		dev := d.devices[s.MAC]
		if dev == nil {
			dev = &device{}
			d.devices[s.MAC] = dev
		}
		key := portKey{port: s.Port, proto: s.Proto}
		if s.V6 {
			dev.v6.port(key).restore(s)
			continue
		}
		dev.v4.port(key).restore(s)
	}
}

// Summary 输出汇总信息。
func (d *Detector) Summary() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logger.Printf("统计：当前跟踪设备 %d 个，累计告警 %d 次；端口上限提前过期 %d 个端口、丢弃 %d 个新端口报文",
		len(d.devices), d.alerts, d.portEvictions, d.portDrops)
}
