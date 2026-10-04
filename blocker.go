package main

import (
	"log"
	"strconv"
	"sync"
)

// Blocker 汇总检测层的告警事件，并在状态变化时执行封禁/解封。
//
// 检测与封禁均以「设备 MAC + 本地端口」为单位：
//   - 某「MAC + 端口」开始告警时封禁该设备在该端口上的 UDP 流量；
//   - 该「MAC + 端口」结束时解封；
//   - 程序退出时对所有仍处于封禁状态的条目兜底解封。
//
// 为避免 IPv4 / IPv6 同端口重复触发，按「MAC + 端口」做引用计数。
// 防火墙命令在后台协程执行，不阻塞抓包与检测。
type Blocker struct {
	fw     *Firewall
	logger *log.Logger
	events chan blockEvent
	done   chan struct{}
	wg     sync.WaitGroup

	mu     sync.Mutex
	active map[string]*banState // "mac:port" -> 该条目的引用计数与 IP
}

// banState 记录某「MAC + 端口」条目的引用计数（IPv4/IPv6 各算一次）与最近的设备 IP。
type banState struct {
	refs int
	ip   string
	mac  string
	port uint16
}

type blockEvent struct {
	ban  bool
	mac  string
	ip   string
	port uint16
}

// NewBlocker 创建并启动封禁协调器。
func NewBlocker(fw *Firewall, logger *log.Logger) *Blocker {
	b := &Blocker{
		fw:     fw,
		logger: logger,
		events: make(chan blockEvent, 256),
		done:   make(chan struct{}),
		active: make(map[string]*banState),
	}
	b.wg.Add(1)
	go b.loop()
	return b
}

// OnAlertStart 实现 AlertSink：某设备某端口开始告警。
func (b *Blocker) OnAlertStart(mac, ip string, port uint16) {
	b.enqueue(blockEvent{ban: true, mac: mac, ip: ip, port: port})
}

// OnAlertEnd 实现 AlertSink：某设备某端口告警结束。
func (b *Blocker) OnAlertEnd(mac, ip string, port uint16) {
	b.enqueue(blockEvent{ban: false, mac: mac, ip: ip, port: port})
}

// enqueue 非阻塞投递事件，队列满时丢弃并告警，避免拖慢检测。
func (b *Blocker) enqueue(e blockEvent) {
	select {
	case b.events <- e:
	default:
		b.logger.Printf("警告：封禁事件队列已满，丢弃 %s:%d 的事件", e.mac, e.port)
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
	key := blockKey(e.mac, e.port)
	b.mu.Lock()
	st := b.active[key]

	if e.ban {
		if st == nil {
			st = &banState{mac: e.mac, port: e.port}
			b.active[key] = st
		}
		st.refs++
		st.ip = e.ip
		first := st.refs == 1
		b.mu.Unlock()

		if first {
			b.apply(true, e.mac, e.ip, e.port)
		}
		return
	}

	if st == nil {
		b.mu.Unlock()
		return
	}
	st.refs--
	last := st.refs <= 0
	ip := st.ip
	if last {
		delete(b.active, key)
	}
	b.mu.Unlock()

	if last {
		b.apply(false, e.mac, ip, e.port)
	}
}

func (b *Blocker) apply(ban bool, mac, ip string, port uint16) {
	if ban {
		if err := b.fw.Ban(mac, ip, port); err != nil {
			b.logger.Printf("封禁设备 %s(%s) 的 UDP 端口 %d 失败：%v", mac, ip, port, err)
			return
		}
		b.logger.Printf("已封禁设备 %s(%s) 的 UDP 端口 %d", mac, ip, port)
		return
	}
	if err := b.fw.Unban(mac, ip, port); err != nil {
		b.logger.Printf("解封设备 %s(%s) 的 UDP 端口 %d 失败：%v", mac, ip, port, err)
		return
	}
	b.logger.Printf("已解封设备 %s(%s) 的 UDP 端口 %d", mac, ip, port)
}

// Close 停止协调器，并对所有仍封禁中的条目兜底解封。
func (b *Blocker) Close() {
	close(b.done)
	b.wg.Wait()

	b.mu.Lock()
	type target struct {
		mac  string
		ip   string
		port uint16
	}
	targets := make([]target, 0, len(b.active))
	for _, st := range b.active {
		targets = append(targets, target{st.mac, st.ip, st.port})
	}
	b.active = make(map[string]*banState)
	b.mu.Unlock()

	for _, t := range targets {
		if err := b.fw.Unban(t.mac, t.ip, t.port); err != nil {
			b.logger.Printf("退出时解封设备 %s(%s) 的 UDP 端口 %d 失败：%v", t.mac, t.ip, t.port, err)
			continue
		}
		b.logger.Printf("退出时已解封设备 %s(%s) 的 UDP 端口 %d", t.mac, t.ip, t.port)
	}
}

func blockKey(mac string, port uint16) string {
	return mac + ":" + strconv.Itoa(int(port))
}

// 确保 Blocker 实现 AlertSink。
var _ AlertSink = (*Blocker)(nil)
