package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// 内置默认值，同时作为命令行参数的默认值与配置文件中缺失项的兜底。
const (
	defaultThreshold     = 20
	defaultWindow        = 60 * time.Second
	defaultAlertDuration = 10 * time.Minute
	defaultInterval      = 2 * time.Second
	defaultPromisc       = true

	// AF_PACKET 内核环形缓冲默认划分：总内存 ≈ block_size * num_blocks = 2MiB，
	// 远小于 pcap/默认配置的十几 MB，适合低内存路由器。
	defaultFrameSize = 65536
	defaultBlockSize = 262144
	defaultNumBlocks = 8

	// 内核要求 block_size 为页大小的整数倍。
	pageSize = 4096
)

// configCandidates 是启动时按顺序尝试加载的配置文件名。
// 前一个不存在或加载失败时，继续尝试下一个（“往下读”）。
var configCandidates = []string{
	"config.toml",
	"pcdn-detect.toml",
}

// configCreateNames 是全部加载失败后，尝试创建默认配置的文件名（按顺序）。
var configCreateNames = []string{
	"pcdn-detect.toml",
}

// defaultConfigTemplate 是自动生成的配置模板（TOML，带注释，便于使用者修改）。
const defaultConfigTemplate = `# pcdn-detect 配置文件（首次启动自动生成于当前工作目录，TOML 格式）
#
# 命令行参数优先于本文件：显式指定的参数会覆盖此处的同名配置。

# 要监听的网卡名称（必填），例如 br-lan、br0、eth0
interface = ""

# 触发次数：同一设备同一端口在检测时长内出现的不同远端公网 IP 数量达到该值即判定疑似 PCDN
threshold = 20

# 检测时长（滑动窗口），支持 "60s"、"5m"、"1h"，也接受整数秒
window = "60s"

# 持续提示时长：期间出现新对端则刷新计时器，超过该时长无新对端则输出「PCDN行为结束」并静默
alert_duration = "10m"

# 是否开启混杂模式
promisc = true

# 检测扫描间隔
interval = "2s"

# 日志时区：IANA 名称（如 Asia/Shanghai）或 POSIX 串（如 CST-8）；留空表示自动读取系统时区
timezone = ""

# 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC（MAC / IPv6 保留前两段与最后一段，如
# 60:21:...:23、2408:8240:...:b2a3；IPv4 保留首尾，中间两段写作 *，如 112.*.*.51），
# 便于对外分享日志；设备外连的远端对端地址不受影响。
# 内网 IPv4（如 192.168.x.x）不会被隐藏。
hide_address = false

# Go 堆内存软上限：达到后运行时会更积极地 GC，避免长期运行时内存膨胀，适合低内存设备。
# 支持 "16MiB"、"24M"、纯字节数等写法；留空表示由运行时自行决定
# （也可改用环境变量 GOMEMLIMIT，该变量由 Go 运行时原生识别）。
# 建议设为设备可用内存的一半左右，例如 128MB 内存的路由器可设 "32MiB"。
memory_limit = ""

# ===== 抓包环形缓冲（低内存设备可调小）=====
# 注：内核环形缓冲总内存 = block_size * num_blocks（字节）。
# 默认 262144 * 8 = 2MiB；若抓包出现丢包可适当增大 num_blocks。
#   frame_size  单个帧上限（字节），须 ≥ 最大报文长度，且能整除 block_size；
#   block_size  每个块大小（字节），须为页大小(4096)与 frame_size 的整数倍；
#   num_blocks  块数量，至少为 1。
[capture]
frame_size = 65536
block_size = 262144
num_blocks = 8

# ===== 黑白名单（按设备 MAC 过滤）=====
# list_mode 选择模式，留空表示不启用（检测全部设备）：
#   "blacklist" = 只检测 blacklist 名单内的设备，其余不检测
#   "whitelist" = whitelist 名单内命中的设备（或指定端口）不检测，其余照常检测
list_mode = ""

# 名单为数组表（[[...]]），每条需写 mac；enabled = false 可临时停用该条（默认 true）
#
# 黑名单（不支持 ports）：
# [[blacklist]]
# mac = "aa:bb:cc:dd:ee:ff"
#
# 白名单（省略 ports = 全部端口）：
# [[whitelist]]
# mac = "aa:bb:cc:dd:ee:ff"
#
# [[whitelist]]
# mac = "11:22:33:44:55:66"
# ports = [40000, 40001]
#
# [[whitelist]]
# mac = "22:33:44:55:66:77"
# ports = ["40000-40010", "80/443"]

# ===== 防火墙对接（自动封禁 / 解封）=====
# enabled = true 时：某设备某端口触发 PCDN 行为即封禁该设备在该端口上的 UDP 流量，
# 「PCDN行为结束」时解封；退出时兜底解封。
# [firewall]
# enabled = false
# backend = "hook"                 # hook / iptables / nftables
#
# backend = "hook"：自定义命令，支持 {mac} {ip} {port} 占位符
# ban_cmd = "nft add element bridge filter pcdn { {mac} . {port} }"
# unban_cmd = "nft delete element bridge filter pcdn { {mac} . {port} }"
#
# backend = "iptables"：iptables 与 ip6tables 的该链按源 MAC + UDP 端口丢弃（默认 FORWARD）
# chain = "FORWARD"
#
# backend = "nftables"：bridge 族按源 MAC + UDP 端口丢弃（表/集合/链可自定义）
# table = "pcdn_detect"
# set = "banned"                   # 实际使用 <set>_v4 / <set>_v6 两个集合
# chain = "forward"
#
# 封禁地址族：true（默认）= 同时封禁设备的 IPv4 与 IPv6；
# false = 按触发到的地址族单独封禁（v4 与 v6 各自独立封禁 / 解封）
# ban_both = true
#
# 单条命令执行超时
# timeout = "5s"
`

// Duration 是 time.Duration 的包装，用于支持 TOML 中 "60s"、"5m" 等写法或整数秒。
type Duration time.Duration

// UnmarshalTOML 支持字符串时长（60s/5m/1h）与整数秒。
func (d *Duration) UnmarshalTOML(v interface{}) error {
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("无效时长 %q（示例：60s、5m、1h）", s)
		}
		*d = Duration(parsed)
		return nil
	case int64:
		*d = Duration(time.Duration(x) * time.Second)
		return nil
	case int:
		*d = Duration(time.Duration(x) * time.Second)
		return nil
	default:
		return fmt.Errorf("时长需要字符串（如 \"60s\"）或整数秒，得到 %T", v)
	}
}

// String 让 Duration 支持 %s 输出（如 1m0s）。
func (d Duration) String() string {
	return time.Duration(d).String()
}

// CaptureConfig 对应 [capture] 配置段：AF_PACKET 内核环形缓冲的划分。
// 环形缓冲总内存 ≈ BlockSize * NumBlocks。默认值面向低内存设备。
type CaptureConfig struct {
	FrameSize int `toml:"frame_size"` // 单个帧上限（字节）
	BlockSize int `toml:"block_size"` // 每个块大小（字节）
	NumBlocks int `toml:"num_blocks"` // 块数量
}

// ringParams 返回经校验的环形缓冲参数；非法或未配置时回退到内置低内存默认值。
// 内核约束：block_size 为页大小整数倍、为 frame_size 整数倍，且 num_blocks ≥ 1。
func (c CaptureConfig) ringParams() (frame, block, blocks int) {
	frame, block, blocks = c.FrameSize, c.BlockSize, c.NumBlocks
	if frame <= 0 || block <= 0 || blocks < 1 ||
		block%pageSize != 0 || block%frame != 0 {
		return defaultFrameSize, defaultBlockSize, defaultNumBlocks
	}
	return frame, block, blocks
}

// FirewallConfig 对应 [firewall] 配置段（自动封禁 / 解封）。
type FirewallConfig struct {
	Enabled  bool     `toml:"enabled"`   // 是否启用
	Backend  string   `toml:"backend"`   // hook / iptables / nftables
	BanCmd   string   `toml:"ban_cmd"`   // hook 后端：封禁命令模板（支持 {mac} {ip} {port} {family}）
	UnbanCmd string   `toml:"unban_cmd"` // hook 后端：解封命令模板
	Chain    string   `toml:"chain"`     // iptables 链名 / nftables 链名
	Table    string   `toml:"table"`     // nftables 表名
	Set      string   `toml:"set"`       // nftables 集合名前缀（实际使用 <set>_v4 / <set>_v6）
	BanBoth  *bool    `toml:"ban_both"`  // 是否同时封禁 IPv4/IPv6；默认 true
	Timeout  Duration `toml:"timeout"`   // 单条命令执行超时
}

// banBothEnabled 返回是否同时封禁 IPv4 与 IPv6（未配置时默认 true）。
func (c FirewallConfig) banBothEnabled() bool {
	return c.BanBoth == nil || *c.BanBoth
}

// Config 对应配置文件内容。
type Config struct {
	Interface     string         `toml:"interface"`
	Threshold     int            `toml:"threshold"`
	Window        Duration       `toml:"window"`
	AlertDuration Duration       `toml:"alert_duration"`
	Promisc       *bool          `toml:"promisc"`
	Interval      Duration       `toml:"interval"`
	Timezone      string         `toml:"timezone"`
	MemoryLimit   string         `toml:"memory_limit"` // Go 堆内存软上限（如 "24MiB"）；留空表示不限制
	HideAddress   bool           `toml:"hide_address"`
	ListMode      string         `toml:"list_mode"`
	Blacklist     []listEntry    `toml:"blacklist"`
	Whitelist     []listEntry    `toml:"whitelist"`
	Capture       CaptureConfig  `toml:"capture"`
	Firewall      FirewallConfig `toml:"firewall"`
}

// listEntry 是名单中的一条。用结构体承载便于将来按 MAC 扩展更多字段
// （如独立阈值、窗口等）；目前支持 mac / ports / enabled。
type listEntry struct {
	MAC     string `toml:"mac"`     // 设备 MAC（必填）
	Ports   []any  `toml:"ports"`   // 端口数组：整数或表达式字符串；留空表示全部端口
	Enabled *bool  `toml:"enabled"` // 该条是否生效，默认 true
}

// isEnabled 返回该条是否生效（未设置 enabled 视为 true）。
func (e listEntry) isEnabled() bool {
	return e.Enabled == nil || *e.Enabled
}

// defaultConfig 返回使用内置默认值的配置。
func defaultConfig() *Config {
	promisc := defaultPromisc
	return &Config{
		Threshold:     defaultThreshold,
		Window:        Duration(defaultWindow),
		AlertDuration: Duration(defaultAlertDuration),
		Promisc:       &promisc,
		Interval:      Duration(defaultInterval),
		Capture: CaptureConfig{
			FrameSize: defaultFrameSize,
			BlockSize: defaultBlockSize,
			NumBlocks: defaultNumBlocks,
		},
	}
}

// applyDefaults 为配置中缺失或非法的项填充内置默认值。
func (c *Config) applyDefaults() {
	if c.Threshold <= 0 {
		c.Threshold = defaultThreshold
	}
	if c.Window <= 0 {
		c.Window = Duration(defaultWindow)
	}
	if c.AlertDuration <= 0 {
		c.AlertDuration = Duration(defaultAlertDuration)
	}
	if c.Interval <= 0 {
		c.Interval = Duration(defaultInterval)
	}
	if c.Promisc == nil {
		promisc := defaultPromisc
		c.Promisc = &promisc
	}
	// 抓包缓冲非法或未配置时回退到内置默认值。
	frame, block, blocks := c.Capture.ringParams()
	c.Capture = CaptureConfig{FrameSize: frame, BlockSize: block, NumBlocks: blocks}
}

// parseConfig 解析 TOML 配置内容；未知键、类型错误等视为解析失败。
func parseConfig(data []byte) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, err
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, 0, len(un))
		for _, k := range un {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("未知配置项：%s", strings.Join(keys, ", "))
	}
	if cfg.ListMode != "" {
		m, err := parseListMode(cfg.ListMode)
		if err != nil {
			return nil, err
		}
		cfg.ListMode = m
	}
	return &cfg, nil
}

// listEntries 把名单条目转换为 NewDeviceFilter 接收的条目字符串。
// enabled = false 的条目会被跳过。
func (c *Config) listEntries() (blacklist, whitelist []string, err error) {
	for _, e := range c.Blacklist {
		if !e.isEnabled() {
			continue
		}
		if strings.TrimSpace(e.MAC) == "" {
			return nil, nil, fmt.Errorf("黑名单条目缺少 mac 字段")
		}
		if len(e.Ports) > 0 {
			return nil, nil, fmt.Errorf("黑名单 %s 不支持端口配置", e.MAC)
		}
		blacklist = append(blacklist, e.MAC)
	}
	for _, e := range c.Whitelist {
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

// parseListMode 解析名单模式，空值表示不启用。
func parseListMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "off", "disable", "disabled":
		return listModeNone, nil
	case "blacklist", "black", "bl":
		return listModeBlacklist, nil
	case "whitelist", "white", "wl":
		return listModeWhitelist, nil
	}
	return "", fmt.Errorf("list_mode 无效 %q（可选 blacklist / whitelist）", s)
}

// parseByteSize 解析内存大小，用于 memory_limit：
// 支持纯字节数或带二进制单位（B/K/KB/KiB/M/MB/MiB/G/GB/GiB，大小写不敏感；
// 单独写 K/M/G 也按 1024 进制），例如 "16MiB"、"24M"、"262144"。空串返回 0。
func parseByteSize(s string) (int64, error) {
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

// configResult 描述一次配置加载的结果。
type configResult struct {
	Config   *Config
	Path     string   // 实际使用的配置文件路径（创建时为新建文件）
	Created  bool     // 是否为本次新建的默认配置文件
	Warnings []string // 加载过程中被跳过的候选文件说明
}

// LoadConfig 按默认候选顺序加载配置（等价于 loadConfig(configCandidates, configCreateNames)）。
func LoadConfig() (*configResult, error) {
	return loadConfig(configCandidates, configCreateNames)
}

// loadConfigFor 在显式指定配置文件时仅使用该文件，否则走默认候选顺序。
func loadConfigFor(explicitPath string, hasExplicit bool) (*configResult, error) {
	if hasExplicit {
		return loadConfig([]string{explicitPath}, []string{explicitPath})
	}
	return loadConfig(configCandidates, configCreateNames)
}

// loadConfig 按 candidates 顺序查找并加载配置文件：
//   - 找到且解析成功：使用该配置；
//   - 存在但解析/读取失败：记录警告并继续尝试下一个候选；
//   - 全部候选都不可用：尝试创建 createNames 中的默认配置文件；
//   - 创建目标已存在导致无法创建：返回错误。
func loadConfig(candidates, createNames []string) (*configResult, error) {
	var warnings []string
	for _, name := range candidates {
		data, err := os.ReadFile(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("读取配置文件 %s 失败，已跳过：%v", name, err))
			continue
		}
		cfg, err := parseConfig(data)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("解析配置文件 %s 失败，已跳过：%v", name, err))
			continue
		}
		cfg.applyDefaults()
		return &configResult{Config: cfg, Path: name, Warnings: warnings}, nil
	}

	// 没有任何可加载的配置：创建默认配置文件。
	name, err := createDefaultConfig(createNames)
	if err != nil {
		if len(warnings) > 0 {
			return nil, fmt.Errorf("%v；且创建默认配置失败：%w", warnings[len(warnings)-1], err)
		}
		return nil, err
	}
	return &configResult{Config: defaultConfig(), Path: name, Created: true, Warnings: warnings}, nil
}

// createDefaultConfig 依次尝试用 names 创建默认配置文件。
// 某个名字已存在时尝试下一个；若全部已存在或创建失败，则返回错误。
func createDefaultConfig(names []string) (string, error) {
	for _, name := range names {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // 名字被占用，尝试下一个
			}
			return "", fmt.Errorf("创建配置文件 %s 失败：%w", name, err)
		}
		if _, err := f.WriteString(defaultConfigTemplate); err != nil {
			f.Close()
			return "", fmt.Errorf("写入配置文件 %s 失败：%w", name, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("关闭配置文件 %s 失败：%w", name, err)
		}
		return name, nil
	}
	return "", fmt.Errorf("配置文件 %s 均已存在，无法创建默认配置", strings.Join(names, "/"))
}
