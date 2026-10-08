package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":              true,
		"1.1.1.1":              true,
		"192.168.1.1":          false,
		"10.0.0.1":             false,
		"172.16.0.1":           false,
		"127.0.0.1":            false,
		"169.254.1.1":          false,
		"224.0.0.1":            false,
		"2400:3200::1":         true,
		"2001:4860:4860::8888": true,
		"fe80::1":              false,
		"fc00::1":              false,
		"::1":                  false,
		"ff02::1":              false,
	}
	for in, want := range cases {
		if got := isPublicIP(netip.MustParseAddr(in)); got != want {
			t.Errorf("isPublicIP(%s)=%v, want %v", in, got, want)
		}
	}
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
// 被丢弃的帧返回 0。分别覆盖 udp_only = true（仅 UDP）与 udp_only = false（TCP/UDP）。
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

	// wantUDPOnly 表示 udp_only = true 时是否放行；wantBoth 表示 udp_only = false 时是否放行。
	tests := []struct {
		name        string
		frame       []byte
		wantUDPOnly bool
		wantBoth    bool
	}{
		{"ARP 丢弃", func() []byte { f := newFrame(); be16(f, 12, 0x0806); return f }(), false, false},
		{"STP 丢弃", func() []byte { f := newFrame(); be16(f, 12, 0x0026); return f }(), false, false},
		{"IPv4 UDP 放行", ipv4(protoUDP), true, true},
		{"IPv4 TCP 仅 udp_only=false 放行", ipv4(protoTCP), false, true},
		{"IPv4 ICMP 丢弃", ipv4(1), false, false},
		{"IPv6 UDP 放行", ipv6(protoUDP), true, true},
		{"IPv6 TCP 仅 udp_only=false 放行", ipv6(protoTCP), false, true},
		{"IPv6 分片头放行", ipv6(44), true, true},
		{"IPv6 ICMPv6 丢弃", ipv6(58), false, false},
		{"单层 VLAN IPv4 UDP 放行", v4SingleTag, true, true},
		{"单层 VLAN IPv6 UDP 放行", v6SingleTag, true, true},
		{"单层 VLAN 内 ARP 丢弃", arpVlan, false, false},
		{"QinQ IPv4 UDP 放行", v4QinQ, true, true},
		{"QinQ IPv6 ICMPv6 丢弃", v6QinQ, false, false},
	}

	// 两种模式分别编译并执行。
	for _, tc := range []struct {
		udpOnly bool
		label   string
	}{{true, "udp_only=true"}, {false, "udp_only=false"}} {
		insns, err := captureBPFInstructions(tc.udpOnly)
		if err != nil {
			t.Fatalf("%s：构建过滤器失败：%v", tc.label, err)
		}
		vm, err := bpf.NewVM(insns)
		if err != nil {
			t.Fatalf("%s：编译过滤器失败：%v", tc.label, err)
		}
		for _, tt := range tests {
			want := tt.wantBoth
			if tc.udpOnly {
				want = tt.wantUDPOnly
			}
			n, err := vm.Run(tt.frame)
			if err != nil {
				t.Errorf("%s %s：VM 执行失败：%v", tc.label, tt.name, err)
				continue
			}
			if got := n > 0; got != want {
				t.Errorf("%s %s：放行=%v，期望 %v", tc.label, tt.name, got, want)
			}
		}
	}
}
