package detector

import (
	"container/heap"
	"net/netip"
	"sort"
)

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
