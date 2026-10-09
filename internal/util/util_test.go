package util

import "testing"

func TestMaskAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"60:21:01:1b:0a:23", "60:21:...:23"},
		{"2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", "2408:8240:...:b2a3"},
		{"112.245.115.51", "112.*.*.51"},
		{"1.2.3", "1.2.3"},
		{"", ""},
	}
	for _, c := range cases {
		if got := maskAddress(c.in); got != c.want {
			t.Errorf("maskAddress(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestShouldMaskDeviceIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", true}, // 公网 IPv6
		{"fe80::1", true},        // 链路本地 IPv6 也隐藏
		{"8.8.8.8", true},        // 公网 IPv4
		{"192.168.1.100", false}, // 内网 IPv4 保留
		{"10.0.0.1", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := shouldMaskDeviceIP(c.ip); got != c.want {
			t.Errorf("shouldMaskDeviceIP(%q) = %v，期望 %v", c.ip, got, c.want)
		}
	}
}
