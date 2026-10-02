package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// observation 是一条抓包解析后的观测记录，由抓包层交给检测层。
type observation struct {
	mac        string // 设备 MAC
	ip         string // 设备 IP
	localPort  uint16 // 设备本地端口
	remoteIP   string // 远端 IP
	remotePort uint16 // 远端端口
	up         bool   // true: 设备 -> 远端（上行）; false: 远端 -> 设备（下行）
	v6         bool   // true 表示该报文为 IPv6
	length     int    // 报文长度（字节）
	ts         time.Time
}

// peer 表示一个远端对端。
type peer struct {
	ip        string
	ports     map[uint16]struct{}
	lastSeen  time.Time
	upBytes   uint64
	downBytes uint64
}

// portStat 表示某设备上一个“本地端口”的对端集合。
type portStat struct {
	port       uint16
	ip         string           // 该端口所用设备本地 IP（与该端口流量同属一个地址族）
	peers      map[string]*peer // key: 远端 IP
	upBytes    uint64
	downBytes  uint64
	alertStart time.Time           // 本轮告警起始时间；零值表示未处于告警中
	reported   map[string]struct{} // 本轮已提示过的对端 IP
}

// portKey 以「端口 + 地址族」为键。同一 MAC 可能同时拥有 IPv4 与 IPv6 地址，
// 必须分开统计，否则设备 IP 会被另一地址族的流量覆盖，导致输出错乱。
type portKey struct {
	port uint16
	v6   bool
}

// device 表示一个被跟踪的设备（以 MAC 标识）。
type device struct {
	mac   string
	ports map[portKey]*portStat
}

// Detector 维护滑动窗口内的连接统计，并在超过阈值时告警。
type Detector struct {
	mu            sync.Mutex
	devices       map[string]*device
	threshold     int           // 触发次数：同一设备同一端口在窗口内出现的不同远端 IP 数量阈值
	window        time.Duration // 检测时长（滑动窗口）
	alertDuration time.Duration // 首次告警后持续提示的最长时间
	logger        *log.Logger
	alerts        int
}

// NewDetector 创建一个检测器。
func NewDetector(threshold int, window, alertDuration time.Duration, logger *log.Logger) *Detector {
	return &Detector{
		devices:       make(map[string]*device),
		threshold:     threshold,
		window:        window,
		alertDuration: alertDuration,
		logger:        logger,
	}
}

// Observe 记录一条观测。对端为非公网地址的记录由抓包层过滤，不会传入。
func (d *Detector) Observe(o observation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	dev := d.devices[o.mac]
	if dev == nil {
		dev = &device{mac: o.mac, ports: make(map[portKey]*portStat)}
		d.devices[o.mac] = dev
	}

	key := portKey{port: o.localPort, v6: o.v6}
	ps := dev.ports[key]
	if ps == nil {
		ps = &portStat{port: o.localPort, ip: o.ip, peers: make(map[string]*peer)}
		dev.ports[key] = ps
	} else if o.ip != "" {
		ps.ip = o.ip
	}

	p := ps.peers[o.remoteIP]
	if p == nil {
		p = &peer{ip: o.remoteIP, ports: make(map[uint16]struct{})}
		ps.peers[o.remoteIP] = p
	}
	if o.remotePort != 0 {
		p.ports[o.remotePort] = struct{}{}
	}
	p.lastSeen = o.ts
	if o.up {
		p.upBytes += uint64(o.length)
		ps.upBytes += uint64(o.length)
	} else {
		p.downBytes += uint64(o.length)
		ps.downBytes += uint64(o.length)
	}
}

// Scan 清理超时对端并检查是否触发告警，需定期调用。
func (d *Detector) Scan(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for mac, dev := range d.devices {
		for key, ps := range dev.ports {
			for ip, p := range ps.peers {
				if now.Sub(p.lastSeen) > d.window {
					delete(ps.peers, ip)
				}
			}

			d.checkPort(dev, ps, now)

			if len(ps.peers) == 0 {
				delete(dev.ports, key)
			}
		}
		if len(dev.ports) == 0 {
			delete(d.devices, mac)
		}
	}
}

// checkPort 根据端口当前的对端情况判定并输出告警。
// 首次超阈值输出「疑似产生PCDN行为」；此后在 alertDuration 内只要出现新的对端 IP，
// 就输出「持续产生PCDN行为」；超过 alertDuration 后静默，直到行为停止（低于阈值）后重置。
func (d *Detector) checkPort(dev *device, ps *portStat, now time.Time) {
	count := len(ps.peers)
	if count < d.threshold {
		// 行为停止：结束本轮告警，允许后续重新触发。
		ps.alertStart = time.Time{}
		ps.reported = nil
		return
	}

	if ps.alertStart.IsZero() {
		// 首次触发。
		ps.alertStart = now
		ips := ps.allPeerIPs()
		ps.reported = make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			ps.reported[ip] = struct{}{}
		}
		d.alerts++
		d.logger.Printf("%s(%s) 的端口 %d 疑似产生PCDN行为（窗口内 %d 个对端IP，上行 %s / 下行 %s），相关IP为: %s",
			dev.mac, ps.ip, ps.port, count, humanBytes(ps.upBytes), humanBytes(ps.downBytes), strings.Join(ips, ", "))
		return
	}

	// 持续告警阶段：仅在 alertDuration 内、且出现新 IP 时提示。
	if now.Sub(ps.alertStart) > d.alertDuration {
		return
	}
	var newIPs []string
	for ip := range ps.peers {
		if _, ok := ps.reported[ip]; !ok {
			ps.reported[ip] = struct{}{}
			newIPs = append(newIPs, ip)
		}
	}
	if len(newIPs) == 0 {
		return
	}
	sort.Strings(newIPs)
	d.alerts++
	d.logger.Printf("%s(%s) 的端口 %d 持续产生PCDN行为（窗口内 %d 个对端IP，上行 %s / 下行 %s），新增相关IP为: %s",
		dev.mac, ps.ip, ps.port, count, humanBytes(ps.upBytes), humanBytes(ps.downBytes), strings.Join(newIPs, ", "))
}

// allPeerIPs 返回当前对端 IP 的排序列表。
func (ps *portStat) allPeerIPs() []string {
	ips := make([]string, 0, len(ps.peers))
	for ip := range ps.peers {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

// Summary 输出汇总信息。
func (d *Detector) Summary() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logger.Printf("统计：当前跟踪设备 %d 个，累计告警 %d 次", len(d.devices), d.alerts)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
