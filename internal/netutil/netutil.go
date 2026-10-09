// Package netutil 提供跨包共享的网络基础类型与判定：设备 MAC、传输层协议号与公网地址判定。
package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// 传输层协议号（与 IPv4 Protocol / IPv6 Next Header 字段一致）。
// 声明为无类型常量，便于在 uint8（报文解析）与 uint32（内核 BPF 过滤器）等场景直接使用。
const (
	ProtoTCP = 6
	ProtoUDP = 17
)

// MAC 是设备的 6 字节 MAC 地址（值类型、可比较）：抓包层可直接由报文原始字节构造，
// 既零分配，又能直接作为 map 键——避免为每个报文分配 MAC 字符串（抓包热路径上最主要的
// 内存分配来源）。
type MAC [6]byte

// String 返回小写冒号分隔的 MAC 字符串，仅在日志等低频路径调用。
func (m MAC) String() string {
	const hexdigits = "0123456789abcdef"
	var b [17]byte
	j := 0
	for i, c := range m {
		if i > 0 {
			b[j] = ':'
			j++
		}
		b[j] = hexdigits[c>>4]
		b[j+1] = hexdigits[c&0x0f]
		j += 2
	}
	return string(b[:])
}

// ParseMAC 把字符串形式的 MAC 解析为 6 字节的 MAC，大小写不敏感。
func ParseMAC(s string) (MAC, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return MAC{}, err
	}
	if len(hw) != 6 {
		return MAC{}, fmt.Errorf("MAC 长度无效：%q", s)
	}
	var k MAC
	copy(k[:], hw)
	return k, nil
}

// IsPublicIP 判断是否为可路由的公网单播地址。
// 内网、环回、链路本地、组播、未指定地址均返回 false。
func IsPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	// IsGlobalUnicast 已排除环回、链路本地、组播与未指定地址；再排除内网段。
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
}
