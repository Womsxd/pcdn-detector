package netutil

import (
	"net/netip"
	"testing"
)

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
		if got := IsPublicIP(netip.MustParseAddr(in)); got != want {
			t.Errorf("IsPublicIP(%s)=%v, want %v", in, got, want)
		}
	}
}
