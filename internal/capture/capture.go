// Package capture 基于 AF_PACKET 抓包并解析以太网 / IPv4 / IPv6 / TCP / UDP 头部。
package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/netutil"
)

const (
	ethHeaderLen  = 14
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88A8

	protoTCP = netutil.ProtoTCP
	protoUDP = netutil.ProtoUDP
)

// Capturer 基于 AF_PACKET(Linux) 内核环形缓冲抓包，等价于 pcap 的抓包能力，
// 但为纯 Go 实现、无需 libpcap/CGO，方便在 OpenWrt 上静态编译部署。
type Capturer struct {
	mu        sync.RWMutex
	tp        *afpacket.TPacket
	iface     string
	promisc   bool
	ring      config.CaptureConfig
	det       *detector.Detector
	localNets []netip.Prefix // 该网卡自身所在网段（含 IPv4/IPv6），用于判定“本端地址”
}

// NewCapturer 打开指定网卡的抓包句柄。
// 环形缓冲大小由 ring 决定（总内存 ≈ block_size * num_blocks），便于在低内存设备上裁剪。
func NewCapturer(iface string, promisc bool, ring config.CaptureConfig, det *detector.Detector) (*Capturer, error) {
	tp, err := newTPacket(iface, promisc, ring)
	if err != nil {
		return nil, err
	}
	c := &Capturer{tp: tp, iface: iface, promisc: promisc, ring: ring, det: det}
	c.loadLocalNets()
	return c, nil
}

// newTPacket 打开指定网卡的 AF_PACKET 句柄，设置混杂模式并附加内核层 BPF 过滤器。
func newTPacket(iface string, promisc bool, ring config.CaptureConfig) (*afpacket.TPacket, error) {
	frame, block, blocks := ring.RingParams()
	opts := []interface{}{
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(frame),
		afpacket.OptBlockSize(block),
		afpacket.OptNumBlocks(blocks),
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

	// 内核层 BPF 过滤（收益最大的一处优化）：ARP、STP、IPv4 ICMP/IGMP、IPv6 ICMPv6/NDP
	// 等无关报文直接在内核环形缓冲之前被丢弃，不再复制到用户态由 handle 解析后丢弃，
	// 从而显著降低用户态处理量与内存带宽（对低内存设备尤为关键）。
	// 默认 protocol = "udp"：仅放行 UDP；"tcp" 仅放行 TCP；"all" 同时放行 UDP 与 TCP。
	// BPF 返回值即 snaplen：内核只复制每个报文的前 snaplen 字节（默认 256B），
	// 负载不再进入用户态；报文长度统计仍取内核记录的 tp_len，不受截断影响。
	filter, err := buildCaptureBPFFilter(ring.CaptureProto(), ring.SnaplenValue())
	if err != nil {
		tp.Close()
		return nil, err
	}
	if err := tp.SetBPF(filter); err != nil {
		tp.Close()
		return nil, fmt.Errorf("设置内核 BPF 过滤器失败：%w", err)
	}
	return tp, nil
}

// bpfLabel 是构建内核过滤器时使用的符号跳转目标。
type bpfLabel int

// bpfJump 记录一条待回填条件跳转的指令下标与其目标标签。
type bpfJump struct {
	idx   int
	label bpfLabel
}

// bpfBuilder 让经典 BPF 过滤器可以按「符号标签」编排跳转：经典 BPF 的跳转是相对
// 偏移（且受 uint8 上限约束），手工填写极易出错，这里先记录目标标签，最后统一换算。
type bpfBuilder struct {
	insns  []bpf.Instruction
	labels map[bpfLabel]int
	jumps  []bpfJump
}

func newBPFBuilder() *bpfBuilder {
	return &bpfBuilder{labels: make(map[bpfLabel]int)}
}

func (b *bpfBuilder) emit(ins bpf.Instruction) { b.insns = append(b.insns, ins) }

// mark 在当前位置定义标签。
func (b *bpfBuilder) mark(l bpfLabel) { b.labels[l] = len(b.insns) }

// jeq 生成「若 A == val 则跳到 label」的条件跳转；不满足时顺序执行下一条指令。
func (b *bpfBuilder) jeq(val uint32, l bpfLabel) {
	b.jumps = append(b.jumps, bpfJump{idx: len(b.insns), label: l})
	b.emit(bpf.JumpIf{Cond: bpf.JumpEqual, Val: val})
}

// resolve 把所有待回填跳转按标签位置换算为相对跳数（SkipTrue）。
func (b *bpfBuilder) resolve() error {
	for _, j := range b.jumps {
		target, ok := b.labels[j.label]
		if !ok {
			return fmt.Errorf("BPF 过滤器引用了未定义的标签 %d", j.label)
		}
		skip := target - (j.idx + 1)
		if skip < 0 || skip > 255 {
			return fmt.Errorf("BPF 跳转越界：标签 %d 相对跳数 %d", j.label, skip)
		}
		ins := b.insns[j.idx].(bpf.JumpIf)
		ins.SkipTrue = uint8(skip)
		b.insns[j.idx] = ins
	}
	return nil
}

// ipv4AcceptProtos 返回 IPv4 在内核层放行的协议集合（随 protocol：udp / tcp / all）。
func ipv4AcceptProtos(protocol string) []uint32 {
	switch protocol {
	case config.ProtoModeTCP:
		return []uint32{protoTCP}
	case config.ProtoModeAll:
		return []uint32{protoTCP, protoUDP}
	default:
		return []uint32{protoUDP}
	}
}

// ipv6AcceptNext 返回 IPv6 首个 Next Header 在内核层放行的取值集合。
//
// 扩展头（0/43/44/51/60/135）一律放行：其最终承载的传输协议无法在内核层判定
// （如分片的大 UDP 必然带 Fragment 头），放行后由用户态 ipv6TransportOffset 继续解析，
// 从而不丢失现有支持的 IPv6 场景。其余取值（如 ICMPv6=58、ESP=50）在用户态 handle 中
// 必然被丢弃，可在内核层直接拦掉。传输层按 protocol 放行 UDP / TCP / 二者。
func ipv6AcceptNext(protocol string) []uint32 {
	nh := []uint32{0, 43, 44, 51, 60, 135}
	switch protocol {
	case config.ProtoModeTCP:
		nh = append(nh, protoTCP)
	case config.ProtoModeAll:
		nh = append(nh, protoTCP, protoUDP)
	default:
		nh = append(nh, protoUDP)
	}
	return nh
}

// captureBPFInstructions 构造内核层经典 BPF 过滤器：按 protocol（udp / tcp / all）放行
// 「可能承载对应传输层协议的 IPv4/IPv6 报文」，其余一律在内核环形缓冲之前丢弃，避免进入
// 用户态再被 handle 丢弃。
//
// 对 protocol = all 而言，该过滤器是 handle 解析逻辑的严格子集——凡被过滤掉的报文，handle
// 原本也会丢弃（IPv4 分片、IPv6 扩展头等场景均不受影响），因此不改变检测语义。
// protocol = udp / tcp 时会额外拦掉另一协议，这是该开关的预期行为（另一种协议不参与统计）。
//
// 以太网帧内的 L3 偏移随 VLAN/QinQ 标签层数变化（每层 4 字节），而经典 BPF 无法对 X
// 寄存器做加法，故按 0/1/2 层标签展开三段分派；更深层的标签极罕见，直接放行交用户态。
//
// snaplen 是放行时的返回值：内核按该长度截断复制，这是本过滤器除了「丢弃无关报文」之外
// 的第二项收益——把每包复制量从整帧（可达 64KiB）降到几十~几百字节，显著降低 CPU 拷贝与
// 环形缓冲占用。解析侧只读头部，负载不参与检测。snaplen 必须 > 0。
func captureBPFInstructions(protocol string, snaplen int) ([]bpf.Instruction, error) {
	accept := uint32(snaplen) // 返回该值表示放行，并只复制前 snaplen 字节

	b := newBPFBuilder()
	acceptLbl := bpfLabel(1)
	depth := func(i int) bpfLabel { return bpfLabel(100 + i) }
	ip4 := func(i int) bpfLabel { return bpfLabel(200 + i) }
	ip6 := func(i int) bpfLabel { return bpfLabel(300 + i) }

	// EtherType 分派：第 i 段的 EtherType 位于 12+4i，L3 起始于 14+4i。
	for i := 0; i < 3; i++ {
		b.mark(depth(i))
		b.emit(bpf.LoadAbsolute{Off: uint32(12 + 4*i), Size: 2})
		switch i {
		case 0, 1:
			b.jeq(etherTypeVLAN, depth(i+1))
			b.jeq(etherTypeQinQ, depth(i+1))
		default:
			// 两层标签之外仍有 VLAN/QinQ：极罕见，放行交用户态解析，避免改变语义。
			b.jeq(etherTypeVLAN, acceptLbl)
			b.jeq(etherTypeQinQ, acceptLbl)
		}
		b.jeq(etherTypeIPv4, ip4(i))
		b.jeq(etherTypeIPv6, ip6(i))
		b.emit(bpf.RetConstant{Val: 0})
	}

	// 各段的协议检查块。
	for i := 0; i < 3; i++ {
		l3 := 14 + 4*i

		// IPv4：协议字段固定位于 L3+9，不在放行集合内的一律丢弃。
		b.mark(ip4(i))
		b.emit(bpf.LoadAbsolute{Off: uint32(l3 + 9), Size: 1})
		for _, proto := range ipv4AcceptProtos(protocol) {
			b.jeq(proto, acceptLbl)
		}
		b.emit(bpf.RetConstant{Val: 0})

		// IPv6：首个 Next Header（L3+6）在放行集合内时放行，其余丢弃。
		b.mark(ip6(i))
		b.emit(bpf.LoadAbsolute{Off: uint32(l3 + 6), Size: 1})
		for _, nh := range ipv6AcceptNext(protocol) {
			b.jeq(nh, acceptLbl)
		}
		b.emit(bpf.RetConstant{Val: 0})
	}

	b.mark(acceptLbl)
	b.emit(bpf.RetConstant{Val: accept})

	if err := b.resolve(); err != nil {
		return nil, err
	}
	return b.insns, nil
}

// buildCaptureBPFFilter 把过滤器汇编为可直接交给 afpacket.SetBPF 的原始指令。
func buildCaptureBPFFilter(protocol string, snaplen int) ([]bpf.RawInstruction, error) {
	if snaplen <= 0 {
		return nil, fmt.Errorf("snaplen 必须大于 0（当前 %d）", snaplen)
	}
	insns, err := captureBPFInstructions(protocol, snaplen)
	if err != nil {
		return nil, err
	}
	return bpf.Assemble(insns)
}

// loadLocalNets 收集网卡自身的网段（含 IPv4 与 IPv6）。
// 在 IPv6 全局地址（无 NAT，设备与对端都是公网地址）场景下，
// 必须依靠“本端网段”而非“公网/内网”来区分设备与远端对端。
// 调用方须持有 c.mu 的写锁（Reconfigure），或处于无并发访问的初始化阶段（NewCapturer）。
func (c *Capturer) loadLocalNets() {
	c.localNets = nil
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
			if p, err := netip.ParsePrefix(ipnet.String()); err == nil {
				c.localNets = append(c.localNets, p)
			}
		}
	}
}

// isLocal 判断 IP 是否属于本端（本网段内或链路本地/环回）。
func (c *Capturer) isLocal(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	c.mu.RLock()
	nets := c.localNets
	c.mu.RUnlock()
	if len(nets) == 0 {
		// 拿不到网卡地址时退化为“非公网即本端”。
		return !netutil.IsPublicIP(ip)
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Reconfigure 原地应用 [capture] 变更：
//   - 网卡与环形缓冲参数均未变时，仅按需在既有 socket 上重设内核 BPF（协议 / snaplen）
//     或切换混杂模式；
//   - 网卡或环形缓冲发生变化时，打开新 socket 成功后原子替换并关闭旧 socket
//     （afpacket 不支持在既有 socket 上修改这两项，重开期间可能有极短丢包）。
//
// 打开新 socket 失败时保留旧 socket 并返回错误，调用方可据此回退。
func (c *Capturer) Reconfigure(ring config.CaptureConfig, promisc bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	frame, block, blocks := ring.RingParams()
	oldFrame, oldBlock, oldBlocks := c.ring.RingParams()
	sameSocket := strings.TrimSpace(ring.Interface) == c.iface &&
		frame == oldFrame && block == oldBlock && blocks == oldBlocks

	if sameSocket {
		snaplen, oldSnaplen := ring.SnaplenValue(), c.ring.SnaplenValue()
		if ring.CaptureProto() != c.ring.CaptureProto() || snaplen != oldSnaplen {
			filter, err := buildCaptureBPFFilter(ring.CaptureProto(), snaplen)
			if err != nil {
				return err
			}
			if err := c.tp.SetBPF(filter); err != nil {
				return fmt.Errorf("重设内核 BPF 过滤器失败：%w", err)
			}
		}
		if promisc != c.promisc {
			if err := c.tp.SetPromiscuous(promisc); err != nil {
				return fmt.Errorf("设置混杂模式失败：%w", err)
			}
		}
		c.ring, c.promisc = ring, promisc
		return nil
	}

	tp, err := newTPacket(ring.Interface, promisc, ring)
	if err != nil {
		return fmt.Errorf("重开抓包 socket 失败（网卡 %s）：%w", ring.Interface, err)
	}
	old := c.tp
	c.tp, c.iface, c.promisc, c.ring = tp, ring.Interface, promisc, ring
	c.loadLocalNets()
	old.Close()
	return nil
}

// Close 关闭抓包句柄。
func (c *Capturer) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
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

		// 持有读锁取当前 socket 并完成读操作：Reconfigure 换 socket 需等待读返回（poll 超时约 1s）。
		c.mu.RLock()
		data, ci, err := c.tp.ZeroCopyReadPacketData()
		c.mu.RUnlock()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// 其它可恢复错误（含换 socket 时旧 fd 被关闭）：短暂让步后重试，连续大量失败则退出。
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
//
// 注意：
//   - data 由抓包层复用，所有下游处理必须在本函数内同步完成；
//   - data 已被内核按 snaplen 截断（默认 256B），只保证包含头部；所有越界读取都返回；
//   - wireLen 是内核记录的线路长度（tp_len），与截断无关，用于流量统计。
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
		srcIP, dstIP netip.Addr
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
		srcIP = addrFrom4(data[off+12 : off+16])
		dstIP = addrFrom4(data[off+16 : off+20])
		l4off = off + ihl
	case etherTypeIPv6:
		if len(data) < off+40 {
			return
		}
		isV6 = true
		srcIP = addrFrom16(data[off+8 : off+24])
		dstIP = addrFrom16(data[off+24 : off+40])
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

	if srcIP == dstIP {
		return
	}

	srcLocal := c.isLocal(srcIP)
	dstLocal := c.isLocal(dstIP)

	var (
		o        detector.Observation
		remoteIP netip.Addr
	)
	switch {
	case srcLocal && !dstLocal:
		// 设备 -> 远端（上行）
		remoteIP = dstIP
		var mac netutil.MAC
		copy(mac[:], data[6:12]) // 零分配：直接从原始字节取源 MAC
		o = detector.Observation{
			MAC:       mac,
			IP:        srcIP,
			LocalPort: srcPort,
			RemoteIP:  dstIP,
			Up:        true,
			V6:        isV6,
			Proto:     proto,
			Length:    wireLen,
			TS:        ts,
		}
	case dstLocal && !srcLocal:
		// 远端 -> 设备（下行）
		remoteIP = srcIP
		var mac netutil.MAC
		copy(mac[:], data[0:6]) // 零分配：直接从原始字节取目的 MAC
		o = detector.Observation{
			MAC:       mac,
			IP:        dstIP,
			LocalPort: dstPort,
			RemoteIP:  srcIP,
			Up:        false,
			V6:        isV6,
			Proto:     proto,
			Length:    wireLen,
			TS:        ts,
		}
	default:
		// 两端同为本端（局域网内部）或同为远端，忽略。
		return
	}

	// 仅统计全球可路由的远端对端，过滤内网/链路本地等噪音。
	if !netutil.IsPublicIP(remoteIP) {
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

// addrFrom4 从 4 字节切片构造 IPv4 地址，零分配。
func addrFrom4(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

// addrFrom16 从 16 字节切片构造 IPv6 地址，零分配。
func addrFrom16(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}
