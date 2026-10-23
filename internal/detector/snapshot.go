package detector

import (
	"sort"

	"pcdn-detect/internal/netutil"
)

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
