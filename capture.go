package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/gopacket/gopacket/afpacket"
)

const (
	ethHeaderLen  = 14
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88A8

	protoTCP = 6
	protoUDP = 17
)

// Capturer 基于 AF_PACKET(Linux) 内核环形缓冲抓包，等价于 pcap 的抓包能力，
// 但为纯 Go 实现、无需 libpcap/CGO，方便在 OpenWrt 上静态编译部署。
type Capturer struct {
	iface     string
	tp        *afpacket.TPacket
	det       *Detector
	localNets []*net.IPNet // 该网卡自身所在网段（含 IPv4/IPv6），用于判定“本端地址”
}

// NewCapturer 打开指定网卡的抓包句柄。
func NewCapturer(iface string, promisc bool, det *Detector) (*Capturer, error) {
	opts := []interface{}{
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(1 << 20),
		afpacket.OptNumBlocks(16),
		afpacket.OptPollTimeout(1 * time.Second),
	}
	tp, err := afpacket.NewTPacket(opts...)
	if err != nil {
		return nil, err
	}
	if promisc {
		// 若内核/驱动不支持混杂模式，忽略错误即可（网桥接口通常无需设置）。
		_ = tp.SetPromiscuous(true)
	}

	c := &Capturer{iface: iface, tp: tp, det: det}
	c.loadLocalNets()
	return c, nil
}

// loadLocalNets 收集网卡自身的网段（含 IPv4 与 IPv6）。
// 在 IPv6 全局地址（无 NAT，设备与对端都是公网地址）场景下，
// 必须依靠“本端网段”而非“公网/内网”来区分设备与远端对端。
func (c *Capturer) loadLocalNets() {
	ifi, err := net.InterfaceByName(c.iface)
	if err != nil {
		return
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			c.localNets = append(c.localNets, ipnet)
		}
	}
}

// isLocal 判断 IP 是否属于本端（本网段内或链路本地/环回）。
func (c *Capturer) isLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if len(c.localNets) == 0 {
		// 拿不到网卡地址时退化为“非公网即本端”。
		return !isPublicIP(ip)
	}
	for _, n := range c.localNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Close 关闭抓包句柄。
func (c *Capturer) Close() {
	if c.tp != nil {
		c.tp.Close()
	}
}

// Run 持续抓包并解析，直到 ctx 被取消。
func (c *Capturer) Run(ctx context.Context) error {
	var errCount int
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		data, ci, err := c.tp.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// 其它可恢复错误：短暂让步后重试，连续大量失败则退出。
			errCount++
			if errCount > 1000 {
				return err
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		errCount = 0
		c.handle(data, ci.Length, ci.Timestamp)
	}
}

// handle 解析单个以太网帧并交给检测器。
// 注意：data 由抓包层复用，所有下游处理必须在本函数内同步完成。
func (c *Capturer) handle(data []byte, wireLen int, ts time.Time) {
	if len(data) < ethHeaderLen {
		return
	}

	off := ethHeaderLen
	ethType := binary.BigEndian.Uint16(data[12:14])

	// 跳过 VLAN / QinQ 标签。
	for ethType == etherTypeVLAN || ethType == etherTypeQinQ {
		if len(data) < off+4 {
			return
		}
		ethType = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
	}

	var (
		srcIP, dstIP net.IP
		proto        uint8
		l4off        int
		isV6         bool
	)

	switch ethType {
	case etherTypeIPv4:
		if len(data) < off+20 {
			return
		}
		ihl := int(data[off]&0x0f) * 4
		if ihl < 20 || len(data) < off+ihl {
			return
		}
		proto = data[off+9]
		srcIP = net.IP(data[off+12 : off+16])
		dstIP = net.IP(data[off+16 : off+20])
		l4off = off + ihl
	case etherTypeIPv6:
		if len(data) < off+40 {
			return
		}
		isV6 = true
		srcIP = net.IP(data[off+8 : off+24])
		dstIP = net.IP(data[off+24 : off+40])
		p, lo, ok := ipv6TransportOffset(data, off)
		if !ok {
			return
		}
		proto = p
		l4off = lo
	default:
		return
	}

	if len(data) < l4off+4 {
		return
	}

	var srcPort, dstPort uint16
	switch proto {
	case protoTCP, protoUDP:
		srcPort = binary.BigEndian.Uint16(data[l4off : l4off+2])
		dstPort = binary.BigEndian.Uint16(data[l4off+2 : l4off+4])
	default:
		return
	}

	if srcIP.Equal(dstIP) {
		return
	}

	srcLocal := c.isLocal(srcIP)
	dstLocal := c.isLocal(dstIP)

	var (
		o        observation
		remoteIP net.IP
	)
	switch {
	case srcLocal && !dstLocal:
		// 设备 -> 远端（上行）
		remoteIP = dstIP
		o = observation{
			mac:        net.HardwareAddr(data[6:12]).String(),
			ip:         srcIP.String(),
			localPort:  srcPort,
			remoteIP:   dstIP.String(),
			remotePort: dstPort,
			up:         true,
			v6:         isV6,
			length:     wireLen,
			ts:         ts,
		}
	case dstLocal && !srcLocal:
		// 远端 -> 设备（下行）
		remoteIP = srcIP
		o = observation{
			mac:        net.HardwareAddr(data[0:6]).String(),
			ip:         dstIP.String(),
			localPort:  dstPort,
			remoteIP:   srcIP.String(),
			remotePort: srcPort,
			up:         false,
			v6:         isV6,
			length:     wireLen,
			ts:         ts,
		}
	default:
		// 两端同为本端（局域网内部）或同为远端，忽略。
		return
	}

	// 仅统计全球可路由的远端对端，过滤内网/链路本地等噪音。
	if !isPublicIP(remoteIP) {
		return
	}

	c.det.Observe(o)
}

// ipv6TransportOffset 跳过 IPv6 扩展头，返回最上层传输协议号与传输层偏移。
// 支持 Hop-by-Hop(0)、Routing(43)、Fragment(44)、AH(51)、Dest-Options(60)、Mobility(135)。
// 若为 ESP(50) 等无法解析或格式非法，返回 ok=false。
func ipv6TransportOffset(data []byte, off int) (proto uint8, l4off int, ok bool) {
	if len(data) < off+40 {
		return 0, 0, false
	}
	next := data[off+6]
	l4off = off + 40
	for i := 0; i < 8; i++ {
		switch next {
		case 0, 43, 60, 135: // 以 8 字节为单位，len 字段为 (值+1)*8
			if len(data) < l4off+2 {
				return 0, 0, false
			}
			hlen := (int(data[l4off+1]) + 1) * 8
			if hlen < 8 || len(data) < l4off+hlen {
				return 0, 0, false
			}
			next = data[l4off]
			l4off += hlen
		case 44: // 分片头，固定 8 字节
			if len(data) < l4off+8 {
				return 0, 0, false
			}
			next = data[l4off]
			l4off += 8
		case 51: // AH，以 4 字节为单位，len 字段为 (值+2)*4
			if len(data) < l4off+2 {
				return 0, 0, false
			}
			hlen := (int(data[l4off+1]) + 2) * 4
			if len(data) < l4off+hlen {
				return 0, 0, false
			}
			next = data[l4off]
			l4off += hlen
		default:
			return next, l4off, true
		}
	}
	return 0, 0, false
}

// isPublicIP 判断是否为可路由的公网单播地址。
// 内网、环回、链路本地、组播、未指定地址均返回 false。
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}
