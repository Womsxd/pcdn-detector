// Package util 提供日志展示相关的通用格式化：字节数量与设备地址掩码（隐私模式）。
package util

import (
	"fmt"
	"net/netip"
	"strings"

	"pcdn-detect/internal/netutil"
)

// HumanBytes 把字节数格式化为便于阅读的字符串（如 3.4MiB）。
func HumanBytes(n uint64) string {
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

// MaskDeviceMAC 返回用于日志展示的设备 MAC。hide 为 true 时掩码为「前两段 + 最后一段」
// （如 60:21:01:1b:0a:23 -> 60:21:...:23）。仅影响展示，不影响过滤与防火墙。
func MaskDeviceMAC(hide bool, mac string) string {
	if !hide {
		return mac
	}
	return maskAddress(mac)
}

// MaskDeviceIP 返回用于日志展示的设备自身 IP。hide 为 true 且该地址为 IPv6 或公网地址时
// 才掩码；内网 IPv4 原样保留。设备外连的远端对端地址不经过此函数，始终完整展示。
func MaskDeviceIP(hide bool, ip string) string {
	if !hide || !shouldMaskDeviceIP(ip) {
		return ip
	}
	return maskAddress(ip)
}

// shouldMaskDeviceIP 判断设备自身 IP 是否需要掩码：IPv6 一律掩码；IPv4 仅公网地址掩码。
func shouldMaskDeviceIP(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	if !addr.Unmap().Is4() {
		return true // IPv6
	}
	return netutil.IsPublicIP(addr)
}

// maskAddress 保留地址的首段与末段，中间省略：
//
//	60:21:01:1b:0a:23                     -> 60:21:...:23
//	2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3 -> 2408:8240:...:b2a3
//	112.245.115.51                        -> 112.*.*.51
//
// 以 ':' 分隔（MAC / IPv6）时保留前两段，省略部分写作 ...；以 '.' 分隔（IPv4）时保留首段，
// 中间两段写作 *（避免与分隔符混淆）；段数不足 4 时原样返回。
func maskAddress(s string) string {
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) < 4 {
			return s
		}
		return parts[0] + ":" + parts[1] + ":...:" + parts[len(parts)-1]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 4 {
		return s
	}
	return parts[0] + ".*.*." + parts[len(parts)-1]
}
