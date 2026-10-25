package detector

import (
	"bytes"
	"sort"

	"pcdn-detect/internal/netutil"
)

// PortKey 是「本地端口 + 传输层协议 + 地址族」的紧凑标识（不含对端与流量信息），
// 供上层统计 / 筛选端口条目，避免为汇总接口构造完整的端口明细视图。
type PortKey struct {
	Port  uint16
	Proto uint8 // netutil.ProtoUDP / netutil.ProtoTCP
	V6    bool
}

// DevicePortKeys 是单个设备当前跟踪的端口键集合（顺序未定义）。
type DevicePortKeys struct {
	MAC  string
	Keys []PortKey
}

// Overview 是检测器的设备级汇总：顶层计数 + 每个设备的端口键集合。
type Overview struct {
	TrackedDevices int
	Alerts         int
	PortEvictions  int64
	PortDrops      int64
	Devices        []DevicePortKeys
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

// Overview 返回设备级汇总（不含端口明细，供 /devices 之类的汇总接口使用）。
// 锁内只复制端口键与计数字段，排序 / MAC 格式化都在锁外完成，避免长时间阻塞抓包与扫描。
func (d *Detector) Overview() Overview {
	type devKeys struct {
		mac  netutil.MAC
		keys []PortKey
	}

	d.mu.Lock()
	out := Overview{
		TrackedDevices: len(d.devices),
		Alerts:         d.alerts,
		PortEvictions:  d.portEvictions,
		PortDrops:      d.portDrops,
	}
	tmp := make([]devKeys, 0, len(d.devices))
	for mac, dev := range d.devices {
		keys := make([]PortKey, 0, len(dev.v4.m)+len(dev.v6.m))
		for key := range dev.v4.m {
			keys = append(keys, PortKey{Port: key.port, Proto: key.proto})
		}
		for key := range dev.v6.m {
			keys = append(keys, PortKey{Port: key.port, Proto: key.proto, V6: true})
		}
		tmp = append(tmp, devKeys{mac: mac, keys: keys})
	}
	d.mu.Unlock()

	sort.Slice(tmp, func(i, j int) bool {
		a, b := tmp[i].mac, tmp[j].mac
		return bytes.Compare(a[:], b[:]) < 0
	})
	out.Devices = make([]DevicePortKeys, 0, len(tmp))
	for _, t := range tmp {
		out.Devices = append(out.Devices, DevicePortKeys{MAC: t.mac.String(), Keys: t.keys})
	}
	return out
}

// DeviceSnapshot 返回单个设备的端口明细（按「端口 → 协议 → 地址族」排序，IPv4 在前）。
// ok 为 false 表示该设备未被跟踪。
// 锁内只复制标量字段，排序与格式化在锁外完成（与 Peers 一致）。
func (d *Detector) DeviceSnapshot(mac netutil.MAC) (DeviceView, bool) {
	d.mu.Lock()
	dev, ok := d.devices[mac]
	if !ok {
		d.mu.Unlock()
		return DeviceView{}, false
	}
	entries := make([]portEntry, 0, len(dev.v4.m)+len(dev.v6.m))
	entries = appendPortEntries(entries, &dev.v4, false)
	entries = appendPortEntries(entries, &dev.v6, true)
	d.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.key.port != b.key.port {
			return a.key.port < b.key.port
		}
		if a.key.proto != b.key.proto {
			return a.key.proto < b.key.proto
		}
		return !a.v6 && b.v6
	})
	dv := DeviceView{MAC: mac.String(), Ports: make([]PortView, 0, len(entries))}
	for _, e := range entries {
		dv.Ports = append(dv.Ports, PortView{
			Port:      e.key.port,
			Proto:     protoName(e.key.proto),
			V6:        e.v6,
			PeerCount: e.peers,
			UpBytes:   e.up,
			DownBytes: e.down,
			Alerting:  e.alerting,
		})
	}
	return dv, true
}

// portEntry 是端口明细在锁内复制出的标量快照（不含对端集合）。
type portEntry struct {
	key      portKey
	v6       bool
	peers    int
	up, down uint64
	alerting bool
}

// appendPortEntries 把某地址族端口表的内容复制为标量快照。
func appendPortEntries[K peerKey](dst []portEntry, t *portsTable[K], v6 bool) []portEntry {
	for key, ps := range t.m {
		dst = append(dst, portEntry{
			key:      key,
			v6:       v6,
			peers:    ps.peers.count(),
			up:       ps.upBytes,
			down:     ps.downBytes,
			alerting: ps.alertStartNano != 0,
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
