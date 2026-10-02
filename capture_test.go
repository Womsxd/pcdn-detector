package main

import (
	"net"
	"testing"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
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
		if got := isPublicIP(net.ParseIP(in)); got != want {
			t.Errorf("isPublicIP(%s)=%v, want %v", in, got, want)
		}
	}
}

func TestIsLocalWithLocalNets(t *testing.T) {
	c := &Capturer{localNets: []*net.IPNet{
		mustCIDR("192.168.1.1/24"),
		mustCIDR("2400:abcd::1/64"),
	}}

	local := []string{"192.168.1.100", "2400:abcd::1234", "fe80::1", "127.0.0.1"}
	for _, ip := range local {
		if !c.isLocal(net.ParseIP(ip)) {
			t.Errorf("%s 应判定为本端", ip)
		}
	}

	remote := []string{"8.8.8.8", "192.168.2.1", "2001:4860:4860::8888"}
	for _, ip := range remote {
		if c.isLocal(net.ParseIP(ip)) {
			t.Errorf("%s 应判定为远端", ip)
		}
	}
}

func TestIsLocalFallbackWithoutNets(t *testing.T) {
	c := &Capturer{}
	if !c.isLocal(net.ParseIP("192.168.1.100")) {
		t.Error("无网卡地址时应退化为“非公网即本端”，192.168.1.100 应为本端")
	}
	if c.isLocal(net.ParseIP("8.8.8.8")) {
		t.Error("无网卡地址时 8.8.8.8 应为远端")
	}
}

func TestIPv6TransportOffset(t *testing.T) {
	// IPv6 头 + TCP，无扩展头。
	direct := make([]byte, 40+20)
	direct[0] = 0x60
	direct[6] = protoTCP
	copy(direct[8:24], net.ParseIP("2400:abcd::1").To16())
	copy(direct[24:40], net.ParseIP("2001:4860:4860::8888").To16())
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
