package main

import (
	"fmt"
	"log"
	"net"
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
	alertStart time.Time           // 本轮最近一次告警（触发或持续）时间；零值表示未处于告警中
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

// AlertSink 接收某「设备 + 本地端口」的告警开始 / 结束事件，用于对接防火墙等外部动作。
type AlertSink interface {
	OnAlertStart(mac, ip string, port uint16)
	OnAlertEnd(mac, ip string, port uint16)
}

// Detector 维护滑动窗口内的连接统计，并在超过阈值时告警。
type Detector struct {
	mu            sync.Mutex
	devices       map[string]*device
	threshold     int           // 触发次数：同一设备同一端口在窗口内出现的不同远端 IP 数量阈值
	window        time.Duration // 检测时长（滑动窗口）
	alertDuration time.Duration // 首次告警后持续提示的最长时间
	filter        *DeviceFilter // 黑白名单过滤器（nil 表示不过滤）
	sink          AlertSink     // 告警回调（nil 表示不回调）
	logger        *log.Logger
	hide          bool // 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC
	alerts        int
}

// SetSink 设置告警回调，需在启动前调用。
func (d *Detector) SetSink(s AlertSink) {
	d.sink = s
}

// NewDetector 创建一个检测器。filter 为 nil 时不做名单过滤。
// hide 为 true 时启用隐私模式，日志中隐藏设备自身的 IPv6 / 公网地址与 MAC。
func NewDetector(threshold int, window, alertDuration time.Duration, filter *DeviceFilter, logger *log.Logger, hide bool) *Detector {
	return &Detector{
		devices:       make(map[string]*device),
		threshold:     threshold,
		window:        window,
		alertDuration: alertDuration,
		filter:        filter,
		logger:        logger,
		hide:          hide,
	}
}

// Observe 记录一条观测。对端为非公网地址的记录由抓包层过滤，不会传入。
func (d *Detector) Observe(o observation) {
	// 黑白名单：不参与检测的「设备 MAC + 端口」直接丢弃。
	if !d.filter.Allow(o.mac, o.localPort) {
		return
	}

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

			// 持续期内即使窗口内对端全部过期也保留端口状态，以便后续新对端继续判定。
			if len(ps.peers) == 0 && ps.alertStart.IsZero() {
				delete(dev.ports, key)
			}
		}
		if len(dev.ports) == 0 {
			delete(d.devices, mac)
		}
	}
}

// checkPort 根据端口当前情况判定并输出告警。
// 首次达到阈值输出「疑似产生PCDN行为」；随后进入持续期：
// 期间只要出现新的对端 IP（哪怕只有 1 个）就输出「持续产生PCDN行为」并刷新计时器，
// 不再要求窗口内对端数达到阈值；若持续 alertDuration 内都没有新对端，
// 则输出「PCDN行为结束」并结束本轮，之后可重新触发。
func (d *Detector) checkPort(dev *device, ps *portStat, now time.Time) {
	if ps.alertStart.IsZero() {
		// 未处于告警中：窗口内对端数达到阈值才触发。
		if len(ps.peers) < d.threshold {
			return
		}
		ps.alertStart = now
		ips := ps.allPeerIPs()
		ps.reported = make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			ps.reported[ip] = struct{}{}
		}
		d.alerts++
		d.logger.Printf("%s(%s) 的端口 %d 疑似产生PCDN行为（近 %s 内 %d 个对端IP，累计上行 %s / 下行 %s），相关IP为: %s",
			maskDeviceMAC(d.hide, dev.mac), maskDeviceIP(d.hide, ps.ip), ps.port, d.window, len(ips), humanBytes(ps.upBytes), humanBytes(ps.downBytes), strings.Join(ips, ", "))
		if d.sink != nil {
			d.sink.OnAlertStart(dev.mac, ps.ip, ps.port)
		}
		return
	}

	// 持续期内长时间没有新对端：本轮结束，允许后续重新触发。
	if now.Sub(ps.alertStart) > d.alertDuration {
		d.logger.Printf("%s(%s) 的端口 %d PCDN行为结束（本轮累计 %d 个对端IP，累计上行 %s / 下行 %s）",
			maskDeviceMAC(d.hide, dev.mac), maskDeviceIP(d.hide, ps.ip), ps.port, len(ps.reported), humanBytes(ps.upBytes), humanBytes(ps.downBytes))
		if d.sink != nil {
			d.sink.OnAlertEnd(dev.mac, ps.ip, ps.port)
		}
		ps.alertStart = time.Time{}
		ps.reported = nil
		return
	}

	// 持续期：任何新出现的对端 IP 都判定为仍在产生 PCDN，并刷新计时器。
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
	ps.alertStart = now
	d.alerts++
	d.logger.Printf("%s(%s) 的端口 %d 持续产生PCDN行为（本轮累计 %d 个对端IP，累计上行 %s / 下行 %s），新增相关IP为: %s",
		maskDeviceMAC(d.hide, dev.mac), maskDeviceIP(d.hide, ps.ip), ps.port, len(ps.reported), humanBytes(ps.upBytes), humanBytes(ps.downBytes), strings.Join(newIPs, ", "))
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

// maskDeviceMAC 返回用于日志展示的设备 MAC。hide 为 true 时掩码为「前两段 + 最后一段」
// （如 60:21:01:1b:0a:23 -> 60:21:...:23）。仅影响展示，不影响过滤与防火墙。
func maskDeviceMAC(hide bool, mac string) string {
	if !hide {
		return mac
	}
	return maskAddress(mac)
}

// maskDeviceIP 返回用于日志展示的设备自身 IP。hide 为 true 且该地址为 IPv6 或公网地址时
// 才掩码；内网 IPv4 原样保留。设备外连的远端对端地址不经过此函数，始终完整展示。
func maskDeviceIP(hide bool, ip string) string {
	if !hide || !shouldMaskDeviceIP(ip) {
		return ip
	}
	return maskAddress(ip)
}

// shouldMaskDeviceIP 判断设备自身 IP 是否需要掩码：IPv6 一律掩码；IPv4 仅公网地址掩码。
func shouldMaskDeviceIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.To4() == nil {
		return true // IPv6
	}
	return isPublicIP(ip)
}

// maskAddress 保留地址的前两段与最后一段，中间省略：
//
//	60:21:01:1b:0a:23                     -> 60:21:...:23
//	2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3 -> 2408:8240:...:b2a3
//	112.245.115.51                        -> 112.245.*.51
//
// 以 ':' 分隔（MAC / IPv6）时省略部分写作 ...，以 '.' 分隔（IPv4）时写作 *（避免与分隔符混淆）；
// 段数不足 4 时原样返回。
func maskAddress(s string) string {
	sep, mask := ".", "*"
	if strings.Contains(s, ":") {
		sep, mask = ":", "..."
	}
	parts := strings.Split(s, sep)
	if len(parts) < 4 {
		return s
	}
	return parts[0] + sep + parts[1] + sep + mask + sep + parts[len(parts)-1]
}
