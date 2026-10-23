package detector

import (
	"net/netip"
	"sort"

	"pcdn-detect/internal/util"
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
	d.logger.Warnf("%s(%s) 的端口 %d(%s) 因端口条目达到上限（每设备 %d 个）且无端口可提前过期被丢弃（累计丢弃 %d 个报文）",
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
