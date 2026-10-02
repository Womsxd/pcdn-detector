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
	port      uint16
	peers     map[string]*peer // key: 远端 IP
	upBytes   uint64
	downBytes uint64
	lastAlert time.Time
}

// device 表示一个被跟踪的设备（以 MAC 标识）。
type device struct {
	mac   string
	ip    string
	ports map[uint16]*portStat
}

// Detector 维护滑动窗口内的连接统计，并在超过阈值时告警。
type Detector struct {
	mu        sync.Mutex
	devices   map[string]*device
	threshold int           // 触发次数：同一设备同一端口在窗口内出现的不同远端 IP 数量阈值
	window    time.Duration // 检测时长（滑动窗口）
	logger    *log.Logger
	alerts    int
}

// NewDetector 创建一个检测器。
func NewDetector(threshold int, window time.Duration, logger *log.Logger) *Detector {
	return &Detector{
		devices:   make(map[string]*device),
		threshold: threshold,
		window:    window,
		logger:    logger,
	}
}

// Observe 记录一条观测。对端为非公网地址的记录由抓包层过滤，不会传入。
func (d *Detector) Observe(o observation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	dev := d.devices[o.mac]
	if dev == nil {
		dev = &device{mac: o.mac, ports: make(map[uint16]*portStat)}
		d.devices[o.mac] = dev
	}
	if o.ip != "" {
		dev.ip = o.ip
	}

	ps := dev.ports[o.localPort]
	if ps == nil {
		ps = &portStat{port: o.localPort, peers: make(map[string]*peer)}
		dev.ports[o.localPort] = ps
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
		for port, ps := range dev.ports {
			for ip, p := range ps.peers {
				if now.Sub(p.lastSeen) > d.window {
					delete(ps.peers, ip)
				}
			}

			count := len(ps.peers)
			if count >= d.threshold {
				// 同一持续超阈值的端口，最多每 window 提醒一次，避免刷屏。
				if ps.lastAlert.IsZero() || now.Sub(ps.lastAlert) >= d.window {
					d.report(dev, ps, count)
					ps.lastAlert = now
				}
			}

			if len(ps.peers) == 0 {
				delete(dev.ports, port)
			}
		}
		if len(dev.ports) == 0 {
			delete(d.devices, mac)
		}
	}
}

// report 按约定格式输出告警：mac(ip) 的 port 疑似产生PCDN行为，相关IP为: ...
func (d *Detector) report(dev *device, ps *portStat, count int) {
	ips := make([]string, 0, len(ps.peers))
	for ip := range ps.peers {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	var b strings.Builder
	fmt.Fprintf(&b, "%s(%s) 的端口 %d 疑似产生PCDN行为（窗口内 %d 个对端IP，上行 %s / 下行 %s），相关IP为:",
		dev.mac, dev.ip, ps.port, count, humanBytes(ps.upBytes), humanBytes(ps.downBytes))
	for _, ip := range ips {
		fmt.Fprintf(&b, "\n\t%s", ip)
	}
	d.alerts++
	d.logger.Println(b.String())
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
