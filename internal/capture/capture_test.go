package capture

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/netutil"
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestIsLocalWithLocalNets(t *testing.T) {
	c := &Capturer{localNets: []netip.Prefix{
		mustPrefix("192.168.1.1/24"),
		mustPrefix("2400:abcd::1/64"),
	}}

	local := []string{"192.168.1.100", "2400:abcd::1234", "fe80::1", "127.0.0.1"}
	for _, ip := range local {
		if !c.isLocal(netip.MustParseAddr(ip)) {
			t.Errorf("%s 应判定为本端", ip)
		}
	}

	remote := []string{"8.8.8.8", "192.168.2.1", "2001:4860:4860::8888"}
	for _, ip := range remote {
		if c.isLocal(netip.MustParseAddr(ip)) {
			t.Errorf("%s 应判定为远端", ip)
		}
	}
}

func TestIsLocalFallbackWithoutNets(t *testing.T) {
	c := &Capturer{}
	if !c.isLocal(netip.MustParseAddr("192.168.1.100")) {
		t.Error("无网卡地址时应退化为“非公网即本端”，192.168.1.100 应为本端")
	}
	if c.isLocal(netip.MustParseAddr("8.8.8.8")) {
		t.Error("无网卡地址时 8.8.8.8 应为远端")
	}
}

func TestIPv6TransportOffset(t *testing.T) {
	// IPv6 头 + TCP，无扩展头。
	direct := make([]byte, 40+20)
	direct[0] = 0x60
	direct[6] = protoTCP
	src := netip.MustParseAddr("2400:abcd::1").As16()
	dst := netip.MustParseAddr("2001:4860:4860::8888").As16()
	copy(direct[8:24], src[:])
	copy(direct[24:40], dst[:])
	proto, off, ok := ipv6TransportOffset(direct, 0)
	if !ok || proto != protoTCP || off != 40 {
		t.Fatalf("无扩展头: proto=%d off=%d ok=%v", proto, off, ok)
	}

	// IPv6 头 + Hop-by-Hop(8字节) + UDP。
	hbh := make([]byte, 40+8+8)
	hbh[0] = 0x60
	hbh[6] = 0 // Hop-by-Hop
	hbh[40] = protoUDP
	hbh[41] = 0 // 长度 => (0+1)*8 = 8
	proto, off, ok = ipv6TransportOffset(hbh, 0)
	if !ok || proto != protoUDP || off != 48 {
		t.Fatalf("Hop-by-Hop: proto=%d off=%d ok=%v", proto, off, ok)
	}

	// 截断报文应返回 ok=false。
	if _, _, ok := ipv6TransportOffset([]byte{0x60}, 0); ok {
		t.Fatal("截断报文不应解析成功")
	}
}

// TestCaptureBPFFilter 用 bpf 包自带的 VM 逐条执行内核过滤器：被放行的帧返回非 0，
// 被丢弃的帧返回 0。分别覆盖 protocol = udp（仅 UDP）、tcp（仅 TCP）与 all（UDP+TCP）。
func TestCaptureBPFFilter(t *testing.T) {
	// 统一的 60 字节以太网帧（含最小填充），避免 VM 越界读取。
	newFrame := func() []byte { return make([]byte, 60) }
	be16 := func(f []byte, off int, v uint16) { binary.BigEndian.PutUint16(f[off:off+2], v) }

	// 无 VLAN 的 IPv4/IPv6 帧，仅设置协议 / Next Header 字段。
	ipv4 := func(proto byte) []byte {
		f := newFrame()
		be16(f, 12, etherTypeIPv4)
		f[14+9] = proto
		return f
	}
	ipv6 := func(next byte) []byte {
		f := newFrame()
		be16(f, 12, etherTypeIPv6)
		f[14+6] = next
		return f
	}
	// 单层 VLAN 与 QinQ，内层 EtherType 由 inner 指定。
	vlan1 := func(inner uint16) []byte {
		f := newFrame()
		be16(f, 12, etherTypeVLAN)
		be16(f, 16, inner)
		return f
	}
	qinq := func(inner uint16) []byte {
		f := newFrame()
		be16(f, 12, etherTypeQinQ)
		be16(f, 16, etherTypeVLAN)
		be16(f, 20, inner)
		return f
	}

	v4SingleTag := vlan1(etherTypeIPv4)
	v4SingleTag[18+9] = protoUDP
	v6SingleTag := vlan1(etherTypeIPv6)
	v6SingleTag[18+6] = protoUDP
	v4QinQ := qinq(etherTypeIPv4)
	v4QinQ[22+9] = protoUDP
	v6QinQ := qinq(etherTypeIPv6)
	v6QinQ[22+6] = 58 // ICMPv6：应丢弃
	arpVlan := vlan1(0x0806)

	// wantUDP / wantTCP / wantAll 分别为三种 protocol 下是否放行。
	type bpfCase struct {
		name    string
		frame   []byte
		wantUDP bool
		wantTCP bool
		wantAll bool
	}
	tests := []bpfCase{
		{"ARP 丢弃", func() []byte { f := newFrame(); be16(f, 12, 0x0806); return f }(), false, false, false},
		{"STP 丢弃", func() []byte { f := newFrame(); be16(f, 12, 0x0026); return f }(), false, false, false},
		{"IPv4 UDP 放行", ipv4(protoUDP), true, false, true},
		{"IPv4 TCP 仅 tcp/all 放行", ipv4(protoTCP), false, true, true},
		{"IPv4 ICMP 丢弃", ipv4(1), false, false, false},
		{"IPv6 UDP 放行", ipv6(protoUDP), true, false, true},
		{"IPv6 TCP 仅 tcp/all 放行", ipv6(protoTCP), false, true, true},
		{"IPv6 分片头放行", ipv6(44), true, true, true},
		{"IPv6 ICMPv6 丢弃", ipv6(58), false, false, false},
		{"单层 VLAN IPv4 UDP 放行", v4SingleTag, true, false, true},
		{"单层 VLAN IPv6 UDP 放行", v6SingleTag, true, false, true},
		{"单层 VLAN 内 ARP 丢弃", arpVlan, false, false, false},
		{"QinQ IPv4 UDP 放行", v4QinQ, true, false, true},
		{"QinQ IPv6 ICMPv6 丢弃", v6QinQ, false, false, false},
	}

	wantOf := func(tt bpfCase, protocol string) bool {
		switch protocol {
		case config.ProtoModeTCP:
			return tt.wantTCP
		case config.ProtoModeAll:
			return tt.wantAll
		default:
			return tt.wantUDP
		}
	}

	// 三种 protocol 分别编译并执行。
	const snap = 256
	for _, mode := range []string{config.ProtoModeUDP, config.ProtoModeTCP, config.ProtoModeAll} {
		insns, err := captureBPFInstructions(mode, snap)
		if err != nil {
			t.Fatalf("protocol=%s：构建过滤器失败：%v", mode, err)
		}
		vm, err := bpf.NewVM(insns)
		if err != nil {
			t.Fatalf("protocol=%s：编译过滤器失败：%v", mode, err)
		}
		for _, tt := range tests {
			want := wantOf(tt, mode)
			n, err := vm.Run(tt.frame)
			if err != nil {
				t.Errorf("protocol=%s %s：VM 执行失败：%v", mode, tt.name, err)
				continue
			}
			if got := n > 0; got != want {
				t.Errorf("protocol=%s %s：放行=%v，期望 %v", mode, tt.name, got, want)
			}
			if want && n != snap {
				t.Errorf("protocol=%s %s：放行返回值应为 snaplen %d，got %d", mode, tt.name, snap, n)
			}
		}
	}
}

// 放行时 BPF 的返回值必须等于 snaplen（内核据此截断复制），丢弃时返回 0。
func TestBPFSnaplen(t *testing.T) {
	frame := make([]byte, 60)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	frame[14+9] = byte(protoUDP)

	for _, snap := range []int{64, 128, 256, 1500} {
		insns, err := captureBPFInstructions(config.ProtoModeUDP, snap)
		if err != nil {
			t.Fatalf("snaplen=%d：构建失败：%v", snap, err)
		}
		vm, err := bpf.NewVM(insns)
		if err != nil {
			t.Fatalf("snaplen=%d：编译失败：%v", snap, err)
		}
		if n, err := vm.Run(frame); err != nil || n != snap {
			t.Fatalf("snaplen=%d：放行返回值 %d（err=%v）", snap, n, err)
		}

		other := make([]byte, 60)
		binary.BigEndian.PutUint16(other[12:14], etherTypeIPv4)
		other[14+9] = 1 // ICMP：丢弃
		if n, err := vm.Run(other); err != nil || n != 0 {
			t.Fatalf("snaplen=%d：丢弃应返回 0，got %d（err=%v）", snap, n, err)
		}
	}

	if _, err := buildCaptureBPFFilter(config.ProtoModeUDP, 0); err == nil {
		t.Fatal("snaplen=0 应报错")
	}
}

// buildIPv4UDPFrame 构造 IPv4 UDP 帧：192.168.1.10:40000 -> 8.8.8.8:1234。
func buildIPv4UDPFrame(payload int) []byte {
	f := make([]byte, 14+20+8+payload)
	binary.BigEndian.PutUint16(f[12:14], etherTypeIPv4)
	f[14] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(f[16:18], uint16(20+8+payload))
	f[14+9] = byte(protoUDP)
	copy(f[14+12:14+16], netip.MustParseAddr("192.168.1.10").AsSlice())
	copy(f[14+16:14+20], netip.MustParseAddr("8.8.8.8").AsSlice())
	binary.BigEndian.PutUint16(f[34:36], 40000)
	binary.BigEndian.PutUint16(f[36:38], 1234)
	copy(f[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	return f
}

// buildIPv6ExtUDPFrame 构造带 200 字节 Hop-by-Hop 扩展头的 IPv6 UDP 帧：
// L4 头位于 254 字节处，正好卡在默认 snaplen(256) 的边缘之外。
func buildIPv6ExtUDPFrame() []byte {
	const ext = 200
	f := make([]byte, 14+40+ext+8)
	binary.BigEndian.PutUint16(f[12:14], etherTypeIPv6)
	f[14] = 0x60
	binary.BigEndian.PutUint16(f[14+4:14+6], uint16(40+ext+8))
	f[14+6] = 0 // Hop-by-Hop
	src := netip.MustParseAddr("2400:abcd::1234").As16()
	dst := netip.MustParseAddr("2001:4860:4860::8888").As16()
	copy(f[14+8:14+24], src[:])
	copy(f[14+24:14+40], dst[:])
	f[54] = byte(protoUDP)  // 扩展头的 Next Header
	f[55] = byte(ext/8 - 1) // 扩展头长度：(值+1)*8
	binary.BigEndian.PutUint16(f[54+ext:54+ext+2], 40000)
	binary.BigEndian.PutUint16(f[54+ext+2:54+ext+4], 1234)
	copy(f[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	return f
}

// snaplen 截断后仍能解析头部：端口/对端/IP 正常，流量统计取线路长度 wireLen。
func TestHandleTruncatedBySnaplen(t *testing.T) {
	frame := buildIPv4UDPFrame(1400)
	det := testDetector()
	c := &Capturer{det: det, localNets: []netip.Prefix{mustPrefix("192.168.1.0/24")}}

	c.handle(frame[:256], len(frame), time.Now()) // 模拟 snaplen=256

	snap := det.Snapshot()
	if snap.TrackedDevices != 1 || len(snap.Devices) != 1 || len(snap.Devices[0].Ports) != 1 {
		t.Fatalf("截断后应正常解析出 1 个设备/端口：%+v", snap)
	}
	p := snap.Devices[0].Ports[0]
	if p.Port != 40000 || p.PeerCount != 1 {
		t.Fatalf("端口统计不符：%+v", p)
	}
	mac, err := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("解析 MAC 失败：%v", err)
	}
	pv, ok := det.Peers(mac, 40000, netutil.ProtoUDP, false, 10)
	if !ok || len(pv.PeerIPs) != 1 || pv.PeerIPs[0] != "8.8.8.8" {
		t.Fatalf("对端解析不符：%+v", pv)
	}
	if p.UpBytes != uint64(len(frame)) {
		t.Fatalf("流量统计应取线路长度 %d，got %d", len(frame), p.UpBytes)
	}
}

// L4 头落在 snaplen 之外的报文（超长 IPv6 扩展头链）会被跳过：不 panic、不计入统计。
func TestHandleDropsPacketBeyondSnaplen(t *testing.T) {
	frame := buildIPv6ExtUDPFrame()
	localNets := []netip.Prefix{mustPrefix("2400:abcd::/64")}

	// 完整帧可解析。
	full := testDetector()
	(&Capturer{det: full, localNets: localNets}).handle(frame, len(frame), time.Now())
	if got := full.Snapshot().TrackedDevices; got != 1 {
		t.Fatalf("完整帧应被统计，tracked=%d", got)
	}

	// 截断到 256B 后 L4 头（254..258）不完整，应被安全跳过。
	cut := testDetector()
	(&Capturer{det: cut, localNets: localNets}).handle(frame[:256], len(frame), time.Now())
	if got := cut.Snapshot().TrackedDevices; got != 0 {
		t.Fatalf("L4 头在 snaplen 之外时应跳过，tracked=%d", got)
	}
}

// 持读锁解析报文时若有写者（Reconfigure / Close）在等待，handle 不得再获取 c.mu：
// Go 的 RWMutex 写者优先，嵌套 RLock 会与写者互等而永久死锁。这里用超时检测该约束。
func TestHandleDoesNotNestReadLockWhileWriterWaits(t *testing.T) {
	c := &Capturer{det: testDetector(), localNets: []netip.Prefix{mustPrefix("192.168.1.0/24")}}
	frame := buildIPv4UDPFrame(100)

	c.mu.RLock() // 模拟 Run 持有读锁
	writerDone := make(chan struct{})
	go func() {
		c.mu.Lock() // 写者开始等待，此后新的 RLock 都会阻塞
		c.mu.Unlock()
		close(writerDone)
	}()
	time.Sleep(20 * time.Millisecond) // 让写者进入等待状态

	handleDone := make(chan struct{})
	go func() {
		c.handle(frame, len(frame), time.Now())
		close(handleDone)
	}()

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("写者等待期间 handle 获取了 c.mu，发生死锁")
	}

	c.mu.RUnlock()
	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handle 结束后写者仍未能取得写锁")
	}
}

// TestSnaplenLive 在真实 AF_PACKET 路径上验证：
//  1. 新的环形缓冲默认值能被内核接受；
//  2. 内核按 snaplen 截断（CaptureLength == snaplen），而 Length 仍是线路长度。
//
// 需要 root/CAP_NET_RAW 与 lo 网卡，否则跳过。
func TestSnaplenLive(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限打开 AF_PACKET")
	}
	if !netIfaceExists("lo") {
		t.Skip("缺少 lo 网卡")
	}

	const snap = 256
	ring := config.CaptureConfig{
		Interface: "lo",
		FrameSize: 2048,
		BlockSize: 65536,
		NumBlocks: 4,
		Snaplen:   snap,
		Protocol:  config.ProtoModeUDP,
	}
	tp, err := newTPacket("lo", false, ring)
	if err != nil {
		t.Skipf("打开 lo 失败（可能缺少 CAP_NET_RAW）：%v", err)
	}
	defer tp.Close()

	conn, err := net.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("建立 UDP 连接失败：%v", err)
	}
	defer conn.Close()
	const payload = 1400
	if _, err := conn.Write(make([]byte, payload)); err != nil {
		t.Fatalf("发送 UDP 报文失败：%v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, ci, err := tp.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			t.Fatalf("读包失败：%v", err)
		}
		if ci.Length < payload {
			continue // 跳过测试自身的其它报文
		}
		if ci.CaptureLength != snap {
			t.Fatalf("CaptureLength 应为 snaplen=%d，got %d（Length=%d）", snap, ci.CaptureLength, ci.Length)
		}
		if ci.Length <= snap {
			t.Fatalf("Length 应为线路长度（>%d），got %d", snap, ci.Length)
		}
		return
	}
	t.Fatalf("5s 内未捕获到测试报文")
}
