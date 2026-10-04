package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 名单模式取值。
const (
	listModeNone      = ""          // 未配置：不做过滤
	listModeBlacklist = "blacklist" // 只检测名单内的设备
	listModeWhitelist = "whitelist" // 名单内命中的设备/端口不检测
)

// DeviceFilter 依据黑白名单决定某个「设备 MAC + 本地端口」是否参与检测。
//
// 语义：
//   - blacklist 模式：只检测名单内的设备，其余一律忽略；
//   - whitelist 模式：名单内命中的设备（或指定端口）不检测，其余照常检测；
//   - 未配置模式：不做过滤，检测全部设备。
type DeviceFilter struct {
	mode      string
	blacklist map[string]struct{}
	whitelist map[string]*portRule
}

// portRule 描述白名单中某 MAC 的端口范围：all 为真表示该 MAC 的全部端口。
type portRule struct {
	all   bool
	ports map[uint16]struct{}
}

// NewDeviceFilter 根据模式与名单构建过滤器，并做格式校验。
func NewDeviceFilter(mode string, blacklist, whitelist []string) (*DeviceFilter, error) {
	f := &DeviceFilter{mode: mode}

	f.blacklist = make(map[string]struct{}, len(blacklist))
	for _, item := range blacklist {
		mac, _, hasPorts, err := parseMacEntry(item)
		if err != nil {
			return nil, fmt.Errorf("黑名单条目无效：%w", err)
		}
		if hasPorts {
			return nil, fmt.Errorf("黑名单不支持端口：%q", item)
		}
		f.blacklist[mac] = struct{}{}
	}

	f.whitelist = make(map[string]*portRule, len(whitelist))
	for _, item := range whitelist {
		mac, ports, hasPorts, err := parseMacEntry(item)
		if err != nil {
			return nil, fmt.Errorf("白名单条目无效：%w", err)
		}
		r := f.whitelist[mac]
		if r == nil {
			r = &portRule{ports: make(map[uint16]struct{})}
			f.whitelist[mac] = r
		}
		if !hasPorts {
			r.all = true
		} else {
			for _, p := range ports {
				r.ports[p] = struct{}{}
			}
		}
	}
	return f, nil
}

// Allow 返回该「设备 MAC + 本地端口」是否参与检测。f 为 nil 时一律放行。
func (f *DeviceFilter) Allow(mac string, port uint16) bool {
	if f == nil || f.mode == listModeNone {
		return true
	}
	key := strings.ToLower(mac)
	switch f.mode {
	case listModeBlacklist:
		_, ok := f.blacklist[key]
		return ok // 只检测名单内
	case listModeWhitelist:
		return !f.whitelistMatch(key, port) // 名单内不检测
	default:
		return true
	}
}

// whitelistMatch 判断该 MAC（含指定端口）是否命中白名单。
func (f *DeviceFilter) whitelistMatch(mac string, port uint16) bool {
	r := f.whitelist[mac]
	if r == nil {
		return false
	}
	if r.all {
		return true
	}
	_, ok := r.ports[port]
	return ok
}

// Enabled 表示是否启用了名单过滤。
func (f *DeviceFilter) Enabled() bool {
	return f != nil && f.mode != listModeNone
}

// Mode 返回当前模式。
func (f *DeviceFilter) Mode() string {
	if f == nil {
		return listModeNone
	}
	return f.mode
}

// Empty 表示黑名单模式下名单为空（会导致不检测任何设备）。
func (f *DeviceFilter) Empty() bool {
	return f != nil && f.mode == listModeBlacklist && len(f.blacklist) == 0
}

// Describe 返回便于阅读的模式描述，用于启动日志。
func (f *DeviceFilter) Describe() string {
	switch {
	case f == nil || f.mode == listModeNone:
		return "未启用（检测全部设备）"
	case f.mode == listModeBlacklist:
		return fmt.Sprintf("黑名单（只检测名单内的 %d 个设备）", len(f.blacklist))
	default:
		exact := 0
		for _, r := range f.whitelist {
			if !r.all {
				exact++
			}
		}
		return fmt.Sprintf("白名单（名单内 %d 个 MAC 不检测，其中 %d 个仅限指定端口）", len(f.whitelist), exact)
	}
}

// parseMacEntry 解析一个名单条目：`MAC` 或 `MAC:端口表达式`。
// 端口表达式支持单个端口、范围 `a-b`、斜杠列表 `a/b/c`（可混用，如 `a-b/c`）。
// 返回规范化（小写冒号分隔）后的 MAC、端口列表，以及是否指定了端口。
func parseMacEntry(raw string) (mac string, ports []uint16, hasPorts bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil, false, fmt.Errorf("空条目")
	}
	macStr := s
	// MAC 固定 6 段；出现第 7 段即视为端口表达式（端口表达式内不含 ':'）。
	if parts := strings.Split(s, ":"); len(parts) >= 7 {
		macStr = strings.Join(parts[:6], ":")
		ports, err = parsePortExpr(strings.Join(parts[6:], ":"))
		if err != nil {
			return "", nil, false, err
		}
		hasPorts = true
	}
	hw, e := net.ParseMAC(macStr)
	if e != nil {
		return "", nil, false, fmt.Errorf("MAC 无效：%q", macStr)
	}
	return hw.String(), ports, hasPorts, nil
}

// parsePortExpr 解析端口表达式：单个端口、范围 `a-b`、斜杠列表，可混用。
func parsePortExpr(expr string) ([]uint16, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("端口表达式为空")
	}
	var ports []uint16
	for _, seg := range strings.Split(expr, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil, fmt.Errorf("端口表达式含空段：%q", expr)
		}
		if i := strings.IndexByte(seg, '-'); i >= 0 {
			lo, err := parsePort(seg[:i])
			if err != nil {
				return nil, err
			}
			hi, err := parsePort(seg[i+1:])
			if err != nil {
				return nil, err
			}
			if lo > hi {
				return nil, fmt.Errorf("端口范围无效：%q", seg)
			}
			for p := int(lo); p <= int(hi); p++ {
				ports = append(ports, uint16(p))
			}
		} else {
			p, err := parsePort(seg)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// parsePort 解析单个端口（0-65535）。
func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("端口无效：%q", s)
	}
	return uint16(n), nil
}
