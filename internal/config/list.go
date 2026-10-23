package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/netutil"
)

// ListEntries 把名单条目转换为 NewDeviceFilter 接收的条目字符串。
// enabled = false 的条目会被跳过。
func (c *Config) ListEntries() (blacklist, whitelist []string, err error) {
	for _, e := range c.Filter.Blacklist {
		if !e.isEnabled() {
			continue
		}
		if strings.TrimSpace(e.MAC) == "" {
			return nil, nil, fmt.Errorf("黑名单条目缺少 mac 字段")
		}
		expr, err := portsExpr(e.Ports)
		if err != nil {
			return nil, nil, fmt.Errorf("黑名单 %s：%w", e.MAC, err)
		}
		if expr == "" {
			blacklist = append(blacklist, e.MAC)
		} else {
			blacklist = append(blacklist, e.MAC+":"+expr)
		}
	}
	for _, e := range c.Filter.Whitelist {
		if !e.isEnabled() {
			continue
		}
		if strings.TrimSpace(e.MAC) == "" {
			return nil, nil, fmt.Errorf("白名单条目缺少 mac 字段")
		}
		expr, err := portsExpr(e.Ports)
		if err != nil {
			return nil, nil, fmt.Errorf("白名单 %s：%w", e.MAC, err)
		}
		if expr == "" {
			whitelist = append(whitelist, e.MAC)
		} else {
			whitelist = append(whitelist, e.MAC+":"+expr)
		}
	}
	return blacklist, whitelist, nil
}

// BlacklistPortWarnings 返回黑名单相关的告警提示：
// 黑名单条目配置了端口时，仅这些端口会被检测——若端口范围不足会导致漏检（缺少拦截），
// 因此提示用户。仅在 blacklist 模式下返回；无此类条目时返回 nil。
func (c *Config) BlacklistPortWarnings() []string {
	if c.Filter.ListMode != filter.ModeBlacklist {
		return nil
	}
	var macs []string
	for _, e := range c.Filter.Blacklist {
		if !e.isEnabled() || strings.TrimSpace(e.MAC) == "" {
			continue
		}
		if len(e.Ports) > 0 {
			macs = append(macs, e.MAC)
		}
	}
	if len(macs) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("黑名单中 %d 个条目配置了端口（%s）：仅这些端口会被检测，若端口范围不足可能导致漏检（缺少拦截），建议留空以检测该设备全部端口",
		len(macs), strings.Join(macs, ", "))}
}

// portsExpr 把端口数组拼接为表达式（如 40000/40001-40010），空数组返回空串。
func portsExpr(ports []any) (string, error) {
	if len(ports) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		switch v := p.(type) {
		case int64:
			parts = append(parts, strconv.FormatInt(v, 10))
		case string:
			parts = append(parts, v)
		default:
			return "", fmt.Errorf("端口元素类型无效（需要整数或字符串）：%T", p)
		}
	}
	return strings.Join(parts, "/"), nil
}

// parseListMode 解析名单模式：**空值默认白名单**（白名单为空即不过滤，等价于检测全部设备）。
// 只有黑名单与白名单两种模式；想「不启用名单」用空白名单即可。
func parseListMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return filter.ModeWhitelist, nil
	case "blacklist", "black", "bl":
		return filter.ModeBlacklist, nil
	case "whitelist", "white", "wl":
		return filter.ModeWhitelist, nil
	}
	return "", fmt.Errorf("list_mode 无效 %q（可选 blacklist / whitelist）", s)
}

// FullBanAllowPorts 返回全端口封禁时放行的 UDP 端口：
//   - items 为空（未配置 / 空数组）：使用内置常用端口（DNS/NTP/DHCP）；
//   - items 非空：**仅**使用这些端口（不叠加内置端口）。
//
// 结果去重并按端口号升序。
func FullBanAllowPorts(items []any) ([]uint16, error) {
	parsed, err := filter.ParsePorts(items)
	if err != nil {
		return nil, fmt.Errorf("[full_ban] allow：%w", err)
	}
	if len(parsed) == 0 {
		parsed = append([]uint16(nil), defaultFullBanAllow...)
	}
	set := make(map[uint16]struct{}, len(parsed))
	for _, p := range parsed {
		set[p] = struct{}{}
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// FullBanAllow 返回配置中生效的全端口封禁放行端口。
func (c *Config) FullBanAllow() ([]uint16, error) {
	return FullBanAllowPorts(c.FullBan.Allow)
}

// FullBanDevices 返回 filter 名单中标记了 full_ban = true 且生效的设备 MAC（小写、去重）。
// 供 full_ban = "device" 模式使用：仅这些设备会触发全 UDP 端口封禁。
func (c *Config) FullBanDevices() ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	add := func(entries []listEntry) error {
		for _, e := range entries {
			if e.FullBan == nil || !*e.FullBan || !e.isEnabled() {
				continue
			}
			if strings.TrimSpace(e.MAC) == "" {
				return fmt.Errorf("full_ban 条目缺少 mac 字段")
			}
			mac, err := netutil.ParseMAC(e.MAC)
			if err != nil {
				return fmt.Errorf("full_ban 条目 MAC 无效：%q", e.MAC)
			}
			s := mac.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
		return nil
	}
	if err := add(c.Filter.Blacklist); err != nil {
		return nil, err
	}
	if err := add(c.Filter.Whitelist); err != nil {
		return nil, err
	}
	return out, nil
}

// listMACs 收集名单条目中满足 keep 条件且生效的设备 MAC（小写、去重）。
func listMACs(entries []listEntry, keep func(listEntry) bool) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, e := range entries {
		if !e.isEnabled() || !keep(e) {
			continue
		}
		if strings.TrimSpace(e.MAC) == "" {
			return nil, fmt.Errorf("条目缺少 mac 字段")
		}
		mac, err := netutil.ParseMAC(e.MAC)
		if err != nil {
			return nil, fmt.Errorf("条目 MAC 无效：%q", e.MAC)
		}
		s := mac.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

// UPnPFilter 描述 UPnP 拦截的设备过滤方式。
type UPnPFilter struct {
	BlockAll bool     // true：拦截全部进入路由器的 UPnP，仅放行 Devices（白名单模式）；false：仅拦截 Devices（黑名单模式）
	Devices  []string // 关联设备 MAC（小写、去重）：BlockAll 时为放行名单，否则为拦截名单
}

// UPnPFilterValue 依据 [filter] list_mode 与 [upnp] mode 计算 UPnP 拦截的过滤方式：
//   - blacklist 模式：仅拦截名单内设备（BlockAll=false）；on=全部黑名单设备，device=标记 upnp = true 的黑名单设备；
//   - whitelist 模式：拦截全部进入路由器的 UPnP，仅放行名单内设备（BlockAll=true）；on=全部白名单设备，device=标记 upnp = true 的白名单设备；
//   - 未启用名单（none）：拦截全部（BlockAll=true）；device 时取两表中标记 upnp = true 的设备作为放行。
//
// off 模式返回零值。
func (c *Config) UPnPFilterValue() (UPnPFilter, error) {
	if !c.UPnP.UPnPEnabled() {
		return UPnPFilter{}, nil
	}
	all := func(listEntry) bool { return true }
	marked := func(e listEntry) bool { return e.UPnP != nil && *e.UPnP }
	keep := all
	if c.UPnP.UPnPMode() == UPnPDevice {
		keep = marked
	}

	switch c.Filter.ListMode {
	case filter.ModeBlacklist:
		devs, err := listMACs(c.Filter.Blacklist, keep)
		return UPnPFilter{BlockAll: false, Devices: devs}, err
	case filter.ModeWhitelist:
		devs, err := listMACs(c.Filter.Whitelist, keep)
		return UPnPFilter{BlockAll: true, Devices: devs}, err
	default:
		// 未启用名单：默认拦截全部；device 模式下取两表中标记的设备作为放行。
		if c.UPnP.UPnPMode() != UPnPDevice {
			return UPnPFilter{BlockAll: true}, nil
		}
		bl, err := listMACs(c.Filter.Blacklist, marked)
		if err != nil {
			return UPnPFilter{}, err
		}
		wl, err := listMACs(c.Filter.Whitelist, marked)
		if err != nil {
			return UPnPFilter{}, err
		}
		return UPnPFilter{BlockAll: true, Devices: mergeMACs(bl, wl)}, nil
	}
}

// mergeMACs 按顺序合并去重两组 MAC（均假定已小写）。
func mergeMACs(groups ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, g := range groups {
		for _, m := range g {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out
}

// ParseUPnPPorts 返回 UPnP 拦截覆盖的目的端口：
//   - items 为空（未配置 / 空数组）：使用内置端口（SSDP 1900 / HTTP 控制 5000）；
//   - items 非空：**仅**使用这些端口（不叠加内置端口）。
//
// 结果去重并按端口号升序。
func ParseUPnPPorts(items []any) ([]uint16, error) {
	parsed, err := filter.ParsePorts(items)
	if err != nil {
		return nil, fmt.Errorf("[upnp] ports：%w", err)
	}
	if len(parsed) == 0 {
		parsed = append([]uint16(nil), defaultUPnPPorts...)
	}
	set := make(map[uint16]struct{}, len(parsed))
	for _, p := range parsed {
		set[p] = struct{}{}
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// UPnPPorts 返回配置中生效的 UPnP 拦截目的端口。
func (c *Config) UPnPPorts() ([]uint16, error) {
	return ParseUPnPPorts(c.UPnP.Ports)
}
