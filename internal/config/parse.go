package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseCaptureProtocol 解析抓包协议（[capture] protocol 与命令行 -P/--protocol）：
// 空值默认 udp，取值 udp / tcp / all（大小写不敏感），非法值报错。
func ParseCaptureProtocol(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", ProtoModeUDP:
		return ProtoModeUDP, nil
	case ProtoModeTCP:
		return ProtoModeTCP, nil
	case ProtoModeAll:
		return ProtoModeAll, nil
	}
	return "", fmt.Errorf("protocol 无效 %q（可选 udp / tcp / all）", s)
}

// CaptureProtoLabel 返回抓包协议模式的展示名（UDP / TCP / UDP+TCP），用于启动日志。
func CaptureProtoLabel(protocol string) string {
	switch protocol {
	case ProtoModeTCP:
		return "TCP"
	case ProtoModeAll:
		return "UDP+TCP"
	default:
		return "UDP"
	}
}

// ParseFullBanMode 解析全端口封禁模式（[firewall] full_ban）：
// 空值 / off 表示关闭，on 对所有设备启用，device 仅对 filter 中标记的设备启用。
func ParseFullBanMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none", "disable", "disabled":
		return FullBanOff, nil
	case "on", "all", "enable", "enabled":
		return FullBanOn, nil
	case "device", "dev", "filter":
		return FullBanDevice, nil
	}
	return "", fmt.Errorf("full_ban 无效 %q（可选 off / on / device）", s)
}

// ParseUPnPMode 解析 UPnP 拦截模式（[upnp] mode）：
// 空值 / off 表示关闭，on 对黑名单内全部设备启用，device 仅对 filter 中标记 upnp = true 的设备启用。
func ParseUPnPMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none", "disable", "disabled":
		return UPnPOff, nil
	case "on", "all", "enable", "enabled":
		return UPnPOn, nil
	case "device", "dev", "filter":
		return UPnPDevice, nil
	}
	return "", fmt.Errorf("upnp 无效 %q（可选 off / on / device）", s)
}

// ParseByteSize 解析内存大小，用于 memory_limit：
// 支持纯字节数或带二进制单位（B/K/KB/KiB/M/MB/MiB/G/GB/GiB，大小写不敏感；
// 单独写 K/M/G 也按 1024 进制），例如 "16MiB"、"24M"、"262144"。空串返回 0。
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil || num < 0 {
		return 0, fmt.Errorf("无效的内存大小 %q（示例：16MiB、24M、262144）", s)
	}
	var mult int64
	switch strings.ToLower(strings.TrimSpace(s[i:])) {
	case "", "b":
		mult = 1
	case "k", "kb", "kib":
		mult = 1 << 10
	case "m", "mb", "mib":
		mult = 1 << 20
	case "g", "gb", "gib":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("无效的内存单位 %q（可用 B/K/M/G）", s[i:])
	}
	return int64(num * float64(mult)), nil
}
