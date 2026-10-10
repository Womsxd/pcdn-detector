// Package config 负责加载与校验 TOML 配置，并定义各项配置的默认值与取值规范。
package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/netutil"
)

// 内置默认值，同时作为命令行参数的默认值与配置文件中缺失项的兜底。
const (
	defaultThreshold     = 20
	defaultWindow        = 60 * time.Second
	defaultAlertDuration = 10 * time.Minute
	defaultInterval      = 2 * time.Second
	defaultPromisc       = true
	// 单端口对端记录上限的默认取值：未配置时为 max(defaultPeerLimit, threshold*peerLimitFactor)；
	// 显式设为 0 表示不限制（关闭该功能）。
	defaultPeerLimit = 1000
	peerLimitFactor  = 10

	// 抓包 / 封禁协议模式（配置项 [capture] protocol）取值。
	ProtoModeUDP = "udp" // 默认：仅 UDP
	ProtoModeTCP = "tcp" // 仅 TCP
	ProtoModeAll = "all" // UDP + TCP

	// 全 UDP 端口封禁模式（配置项 [firewall] full_ban）取值。
	FullBanOff    = "off"    // 默认：关闭
	FullBanOn     = "on"     // 对所有设备启用
	FullBanDevice = "device" // 仅对 filter 中标记 full_ban = true 的设备启用

	// 全端口封禁的触发阈值默认值：某设备被封禁的不同端口数达到该值后触发。
	defaultFullBanThreshold = 5

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

// defaultFullBanAllow 是全 UDP 端口封禁时内置放行的常用 UDP 端口：
// DNS(53)、NTP(123)、DHCP(67/68)、DHCPv6(546/547)，避免设备断网。
// 仅在 [full_ban] allow 为空（未配置 / 空数组）时生效；一旦显式配置则以其为准（不叠加）。
var defaultFullBanAllow = []uint16{53, 123, 67, 68, 546, 547}

// defaultConfigTemplate 是自动生成的配置模板（TOML，带注释，便于使用者修改）。
const defaultConfigTemplate = `# pcdn-detect 配置文件（首次启动自动生成于当前工作目录，TOML 格式）
#
# 命令行参数优先于本文件：显式指定的参数会覆盖此处的同名配置。
# 配置按功能分块：[detect] 检测、[capture] 抓包、[memory] 内存、
# [log] 日志展示、[filter] 黑白名单、[firewall] 防火墙对接、[full_ban] 全端口封禁（后两者默认注释）。

# ===== 检测参数 =====
[detect]
# 触发次数：同一设备同一端口在检测时长内出现的不同远端公网 IP 数量达到该值即判定疑似 PCDN
threshold = 20

# 检测时长（滑动窗口），支持 "60s"、"5m"、"1h"，也接受整数秒
window = "60s"

# 持续提示时长：期间只要该端口仍有流量（任意对端，无论新旧）就刷新计时器；超过该时长
# 没有任何流量则输出「PCDN行为结束」并静默（期间出现新对端时额外输出「持续产生PCDN行为」）
alert_duration = "10m"

# 检测扫描间隔
interval = "2s"

# ===== 抓包 =====
[capture]
# 要监听的网卡名称（必填），例如 br-lan、br0、eth0
interface = ""

# 是否开启混杂模式
promisc = true

# 抓包环形缓冲：总内存 = block_size * num_blocks（字节）。
# 默认 262144 * 8 = 2MiB；若抓包出现丢包可适当增大 num_blocks。
#   frame_size  单个帧上限（字节），须 ≥ 最大报文长度，且能整除 block_size；
#   block_size  每个块大小（字节），须为页大小(4096)与 frame_size 的整数倍；
#   num_blocks  块数量，至少为 1。
frame_size = 65536
block_size = 262144
num_blocks = 8

# protocol 为内核层过滤器放行的传输层协议（默认 "udp"）：
#   "udp" = 仅放行 UDP（默认，PCDN 以 UDP 为主，可大幅减少内核→用户态的处理量与内存带宽）；
#   "tcp" = 仅放行 TCP；
#   "all" = 同时放行 UDP 与 TCP（TCP 流量也参与统计）。
# 三种取值都会在内核层丢弃 ARP、STP、ICMP/ICMPv6 等无关报文。
# 防火墙的封禁协议随此设置变化（封禁抓包层实际统计的协议）。
protocol = "udp"

# ===== 内存 =====
[memory]
# Go 堆内存软上限：达到后运行时会更积极地 GC，避免长期运行时内存膨胀，适合低内存设备。
# 支持 "16MiB"、"24M"、纯字节数等写法；留空表示由运行时自行决定
# （也可改用环境变量 GOMEMLIMIT，该变量由 Go 运行时原生识别）。
# 建议设为设备可用内存的一半左右，例如 128MB 内存的路由器可设 "32MiB"。
memory_limit = ""

# 低内存模式：开启后，某「设备 + 端口」一旦达到阈值触发告警，即清空已记录的远端对端 IP
# 列表并停止记录新的对端 IP，只保留触发状态（告警续期 / 累计流量）继续统计。
# 适用于内存极度受限的设备：告警后该端口的对端统计不再随对端数量增长。
# 代价：该端口告警期间不再输出「持续产生PCDN行为（新增相关IP）」，也不再展示持续新增的对端 IP。
low_memory = false

# 单端口对端记录上限：同一「设备 + 端口」在窗口内最多记录的对端 IP 数量，防止单个端口
# 的对端统计无限增长占用内存。达到上限后不再记录新的对端 IP（已有对端仍照常刷新与累计，
# 端口级流量仍完整累计）。取值说明：
#   - 省略（保持注释）：默认取 max(1000, threshold × 10)；
#     开启低内存模式（low_memory = true）时改为 threshold（达阈值即触发并清空对端，无需保留更多）；
#   - 0：不限制（关闭该功能）；
#   - 大于 0 但小于 threshold：自动提升为 threshold（保证仍能达到触发阈值）。
# 内存或对端规模较大的场景可显式调大。
# peer_limit = 1000

# ===== 日志展示 =====
[log]
# 日志时区：IANA 名称（如 Asia/Shanghai）或 POSIX 串（如 CST-8）；留空表示自动读取系统时区
timezone = ""

# 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC（MAC / IPv6 保留前两段与最后一段，如
# 60:21:...:23、2408:8240:...:b2a3；IPv4 保留首尾，中间两段写作 *，如 112.*.*.51），
# 便于对外分享日志；设备外连的远端对端地址不受影响。
# 内网 IPv4（如 192.168.x.x）不会被隐藏。
hide_address = false

# ===== 黑白名单（按设备 MAC 过滤）=====
[filter]
# list_mode 选择模式，留空表示不启用（检测全部设备）：
#   "blacklist" = 只检测 blacklist 名单内的设备，其余不检测
#   "whitelist" = whitelist 名单内命中的设备（或指定端口）不检测，其余照常检测
list_mode = ""

# 名单为数组表（[[filter.blacklist]] / [[filter.whitelist]]），每条需写 mac；
# enabled = false 可临时停用该条（默认 true）
#
# 黑名单（省略 ports = 该设备全部端口；指定 ports 则只检测这些端口，范围不足可能漏检）：
# [[filter.blacklist]]
# mac = "aa:bb:cc:dd:ee:ff"
#
# [[filter.blacklist]]
# mac = "11:22:33:44:55:66"
# ports = [40000, 40001]
#
# 白名单（省略 ports = 全部端口）：
# [[filter.whitelist]]
# mac = "aa:bb:cc:dd:ee:ff"
#
# [[filter.whitelist]]
# mac = "11:22:33:44:55:66"
# ports = [40000, 40001]
#
# [[filter.whitelist]]
# mac = "22:33:44:55:66:77"
# ports = ["40000-40010", "80/443"]

# ===== 防火墙对接（自动封禁 / 解封）=====
# enabled = true 时：某设备某端口触发 PCDN 行为即封禁该设备在该端口上的流量，
# 「PCDN行为结束」时解封；退出时兜底解封。
# 封禁协议随触发报文：UDP 触发只封 UDP，TCP 触发只封 TCP。
# [firewall]
# enabled = false
# backend = "hook"                 # hook / iptables / nftables
#
# backend = "hook"：自定义命令，支持 {mac} {ip} {port} {family} {proto} 占位符
# ban_cmd = "nft add element bridge filter banned_{family}_{proto} { {mac} . {port} }"
# unban_cmd = "nft delete element bridge filter banned_{family}_{proto} { {mac} . {port} }"
#
# backend = "iptables"：iptables 与 ip6tables 的该链按源 MAC + 触发协议 + 源端口丢弃（默认 FORWARD）
# chain = "FORWARD"
#
# backend = "nftables"：bridge 族按源 MAC + 触发协议 + 源端口丢弃（表/集合/链可自定义；
# 集合按「地址族 + 协议」拆分为 <set>_<family>_<proto>，如 banned_v4_udp）
# table = "pcdn_detect"
# set = "banned"                   # 实际使用 <set>_v4_udp / _v4_tcp / _v6_udp / _v6_tcp
# chain = "forward"
#
# 封禁地址族：true（默认）= 同时封禁设备的 IPv4 与 IPv6；
# false = 按触发到的地址族单独封禁（v4 与 v6 各自独立封禁 / 解封）
# ban_both = true
#
# 单条命令执行超时
# timeout = "5s"

# ===== 全 UDP 端口封禁模式（独立配置块）=====
# 在端口封禁之上叠加的设备级全端口封禁（依赖 [firewall] 启用，复用其后端）。
# 某设备「被封禁的不同端口数」达到 threshold 后触发；触发后对该设备封禁全部 UDP 端口，
# 但放行 allow 指定的端口（留空则为内置常用端口：DNS 53 / NTP 123 / DHCP 67,68 / DHCPv6 546,547）；
# 被封禁端口全部解除（计数归零）时自动解除。
# [full_ban]
# mode = "off"                    # off（默认）/ on（全部设备）/ device（仅 filter 中标 full_ban = true 的设备）
# threshold = 5                   # 触发阈值：被封禁的不同端口数达到该值后触发
#
# 全端口封禁时仍放行的 UDP 端口（元素可为整数或表达式字符串）。
# 留空（或删除该行）时使用内置常用端口：[53, 123, 67, 68, 546, 547]（DNS/NTP/DHCP）。
# 显式配置时以其为准（不再叠加内置端口），例如：
# allow = [53, 123, 67, 68, 546, 547]
#
# hook 后端专用：全端口封禁 / 解封命令，支持 {mac} 与 {ports} 占位符（{ports} 为放行端口逗号列表）
# ban_cmd = ""
# unban_cmd = ""
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

// DetectConfig 对应 [detect] 配置段：检测阈值与时间参数。
type DetectConfig struct {
	Threshold     int      `toml:"threshold"`      // 触发次数：窗口内不同远端公网 IP 数阈值
	Window        Duration `toml:"window"`         // 检测时长（滑动窗口）
	AlertDuration Duration `toml:"alert_duration"` // 持续提示时长
	Interval      Duration `toml:"interval"`       // 检测扫描间隔
}

// CaptureConfig 对应 [capture] 配置段：抓包网卡与 AF_PACKET 内核环形缓冲的划分。
// 环形缓冲总内存 ≈ BlockSize * NumBlocks。默认值面向低内存设备。
type CaptureConfig struct {
	Interface string `toml:"interface"`  // 要监听的网卡名称
	Promisc   *bool  `toml:"promisc"`    // 是否开启混杂模式；默认 true
	FrameSize int    `toml:"frame_size"` // 单个帧上限（字节）
	BlockSize int    `toml:"block_size"` // 每个块大小（字节）
	NumBlocks int    `toml:"num_blocks"` // 块数量
	Protocol  string `toml:"protocol"`   // 内核层过滤器放行的协议：udp / tcp / all；默认 udp
}

// MemoryConfig 对应 [memory] 配置段：内存 / 资源控制。
type MemoryConfig struct {
	Limit     string `toml:"memory_limit"` // Go 堆内存软上限（如 "24MiB"）；留空表示不限制
	LowMemory bool   `toml:"low_memory"`   // 低内存模式：触发告警后清空对端列表且不再记录新对端
	PeerLimit *int   `toml:"peer_limit"`   // 单端口对端记录上限；nil = 用默认值，0 = 不限制
}

// LogConfig 对应 [log] 配置段：日志时区与展示。
type LogConfig struct {
	Timezone    string `toml:"timezone"`     // 日志时区；留空表示自动读取系统时区
	HideAddress bool   `toml:"hide_address"` // 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC
}

// FilterConfig 对应 [filter] 配置段：按设备 MAC 的黑白名单。
type FilterConfig struct {
	ListMode  string      `toml:"list_mode"` // 名单模式：留空 / blacklist / whitelist
	Blacklist []listEntry `toml:"blacklist"` // 黑名单条目
	Whitelist []listEntry `toml:"whitelist"` // 白名单条目
}

// CaptureProto 返回经规范化的抓包协议（udp / tcp / all）；未配置或非法时回退默认 udp。
func (c CaptureConfig) CaptureProto() string {
	switch strings.ToLower(strings.TrimSpace(c.Protocol)) {
	case ProtoModeTCP:
		return ProtoModeTCP
	case ProtoModeAll:
		return ProtoModeAll
	default:
		return ProtoModeUDP
	}
}

// RingParams 返回经校验的环形缓冲参数；非法或未配置时回退到内置低内存默认值。
// 内核约束：block_size 为页大小整数倍、为 frame_size 整数倍，且 num_blocks ≥ 1。
func (c CaptureConfig) RingParams() (frame, block, blocks int) {
	frame, block, blocks = c.FrameSize, c.BlockSize, c.NumBlocks
	if frame <= 0 || block <= 0 || blocks < 1 ||
		block%pageSize != 0 || block%frame != 0 {
		return defaultFrameSize, defaultBlockSize, defaultNumBlocks
	}
	return frame, block, blocks
}

// EffectivePeerLimit 计算生效的单端口对端记录上限：
//   - raw 为 nil（未配置）：默认 max(defaultPeerLimit, threshold*peerLimitFactor)；
//     低内存模式（lowMemory）下改为 threshold——该模式达到阈值即触发并清空对端，
//     无需保留远超阈值的对端，把触发前的对端内存收敛到刚好够用；
//   - raw 非 nil：取 *raw（显式 0 表示不限制），显式配置始终优先于低内存默认；
//
// 最后统一规范化：<=0 归 0（不限制），0 < v < threshold 时提升为 threshold。
func EffectivePeerLimit(raw *int, threshold int, lowMemory bool) int {
	v := defaultPeerLimit
	if scaled := threshold * peerLimitFactor; scaled > v {
		v = scaled
	}
	if lowMemory {
		v = threshold
	}
	if raw != nil {
		v = *raw
	}
	return NormalizePeerLimit(v, threshold)
}

// PeerLimitValue 返回配置中生效的单端口对端记录上限（以配置自身的 threshold 计算默认值）。
func (c *Config) PeerLimitValue() int {
	return EffectivePeerLimit(c.Memory.PeerLimit, c.Detect.Threshold, c.Memory.LowMemory)
}

// NormalizePeerLimit 规范化单端口对端记录上限：
//   - limit <= 0：返回 0，表示不限制（关闭）；
//   - 0 < limit < threshold：返回 threshold（保证仍能达到触发阈值）；
//   - limit >= threshold：原样返回。
func NormalizePeerLimit(limit, threshold int) int {
	if limit <= 0 {
		return 0
	}
	if limit < threshold {
		return threshold
	}
	return limit
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

// BanBothEnabled 返回是否同时封禁 IPv4 与 IPv6（未配置时默认 true）。
func (c FirewallConfig) BanBothEnabled() bool {
	return c.BanBoth == nil || *c.BanBoth
}

// FullBanConfig 对应独立的 [full_ban] 配置段：在端口封禁之上叠加的
// 「全 UDP 端口封禁」模式（设备级）。依赖 [firewall] 启用（复用其后端）。
type FullBanConfig struct {
	Mode      string `toml:"mode"`      // off / on / device；默认 off
	Threshold int    `toml:"threshold"` // 触发阈值：被封禁的不同端口数达到该值
	Allow     []any  `toml:"allow"`     // 放行的 UDP 端口（整数或表达式字符串）；为空时用内置常用端口
	BanCmd    string `toml:"ban_cmd"`   // hook 后端：全端口封禁命令模板（{mac} {ports}）
	UnbanCmd  string `toml:"unban_cmd"` // hook 后端：全端口解封命令模板
}

// FullBanMode 返回规范化的全端口封禁模式（未配置时视为 off）。
func (c FullBanConfig) FullBanMode() string {
	if c.Mode == "" {
		return FullBanOff
	}
	return c.Mode
}

// FullBanEnabled 返回是否启用全 UDP 端口封禁模式（mode != off）。
func (c FullBanConfig) FullBanEnabled() bool {
	return c.FullBanMode() != FullBanOff
}

// FullBanThresholdValue 返回生效的全端口封禁触发阈值（未配置或非法时用默认值）。
func (c FullBanConfig) FullBanThresholdValue() int {
	if c.Threshold <= 0 {
		return defaultFullBanThreshold
	}
	return c.Threshold
}

// Config 对应配置文件内容，按功能分块。
type Config struct {
	Detect   DetectConfig   `toml:"detect"`   // 检测阈值与时间参数
	Capture  CaptureConfig  `toml:"capture"`  // 抓包网卡与环形缓冲
	Memory   MemoryConfig   `toml:"memory"`   // 内存 / 资源控制
	Log      LogConfig      `toml:"log"`      // 日志时区与展示
	Filter   FilterConfig   `toml:"filter"`   // 黑白名单
	Firewall FirewallConfig `toml:"firewall"` // 防火墙对接
	FullBan  FullBanConfig  `toml:"full_ban"` // 全 UDP 端口封禁模式（独立配置块）
}

// listEntry 是名单中的一条。用结构体承载便于将来按 MAC 扩展更多字段
// （如独立阈值、窗口等）；目前支持 mac / ports / enabled / full_ban。
type listEntry struct {
	MAC     string `toml:"mac"`      // 设备 MAC（必填）
	Ports   []any  `toml:"ports"`    // 端口数组：整数或表达式字符串；留空表示全部端口
	Enabled *bool  `toml:"enabled"`  // 该条是否生效，默认 true
	FullBan *bool  `toml:"full_ban"` // 是否为该设备启用全 UDP 端口封禁（full_ban = "device" 时使用）
}

// isEnabled 返回该条是否生效（未设置 enabled 视为 true）。
func (e listEntry) isEnabled() bool {
	return e.Enabled == nil || *e.Enabled
}

// DefaultConfig 返回使用内置默认值的配置。
func DefaultConfig() *Config {
	promisc := defaultPromisc
	return &Config{
		Detect: DetectConfig{
			Threshold:     defaultThreshold,
			Window:        Duration(defaultWindow),
			AlertDuration: Duration(defaultAlertDuration),
			Interval:      Duration(defaultInterval),
		},
		Capture: CaptureConfig{
			Promisc:   &promisc,
			FrameSize: defaultFrameSize,
			BlockSize: defaultBlockSize,
			NumBlocks: defaultNumBlocks,
			Protocol:  ProtoModeUDP,
		},
	}
}

// applyDefaults 为配置中缺失或非法的项填充内置默认值。
func (c *Config) applyDefaults() {
	if c.Detect.Threshold <= 0 {
		c.Detect.Threshold = defaultThreshold
	}
	if c.Detect.Window <= 0 {
		c.Detect.Window = Duration(defaultWindow)
	}
	if c.Detect.AlertDuration <= 0 {
		c.Detect.AlertDuration = Duration(defaultAlertDuration)
	}
	if c.Detect.Interval <= 0 {
		c.Detect.Interval = Duration(defaultInterval)
	}
	if c.Capture.Promisc == nil {
		promisc := defaultPromisc
		c.Capture.Promisc = &promisc
	}
	// 抓包缓冲非法或未配置时回退到内置默认值；protocol 未配置时默认 udp。
	// 注意：只更新缓冲相关字段，保留 Interface / Promisc。
	frame, block, blocks := c.Capture.RingParams()
	proto := c.Capture.CaptureProto()
	c.Capture.FrameSize, c.Capture.BlockSize, c.Capture.NumBlocks, c.Capture.Protocol = frame, block, blocks, proto
	// 全端口封禁模式：未配置时默认 off；阈值非法时回退默认值。
	if c.FullBan.Mode == "" {
		c.FullBan.Mode = FullBanOff
	}
	if c.FullBan.Threshold <= 0 {
		c.FullBan.Threshold = defaultFullBanThreshold
	}
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
	if cfg.Filter.ListMode != "" {
		m, err := parseListMode(cfg.Filter.ListMode)
		if err != nil {
			return nil, err
		}
		cfg.Filter.ListMode = m
	}
	proto, err := ParseCaptureProtocol(cfg.Capture.Protocol)
	if err != nil {
		return nil, err
	}
	cfg.Capture.Protocol = proto
	fb, err := ParseFullBanMode(cfg.FullBan.Mode)
	if err != nil {
		return nil, err
	}
	cfg.FullBan.Mode = fb
	return &cfg, nil
}

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

// parseListMode 解析名单模式，空值表示不启用。
func parseListMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "off", "disable", "disabled":
		return filter.ModeNone, nil
	case "blacklist", "black", "bl":
		return filter.ModeBlacklist, nil
	case "whitelist", "white", "wl":
		return filter.ModeWhitelist, nil
	}
	return "", fmt.Errorf("list_mode 无效 %q（可选 blacklist / whitelist）", s)
}

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

// Result 描述一次配置加载的结果。
type Result struct {
	Config   *Config
	Path     string   // 实际使用的配置文件路径（创建时为新建文件）
	Created  bool     // 是否为本次新建的默认配置文件
	Warnings []string // 加载过程中被跳过的候选文件说明
}

// LoadConfig 按默认候选顺序加载配置（等价于 loadConfig(configCandidates, configCreateNames)）。
func LoadConfig() (*Result, error) {
	return loadConfig(configCandidates, configCreateNames)
}

// LoadConfigFor 在显式指定配置文件时仅使用该文件（且不自动创建），否则走默认候选顺序。
func LoadConfigFor(explicitPath string, hasExplicit bool) (*Result, error) {
	if hasExplicit {
		return loadExplicit(explicitPath)
	}
	return loadConfig(configCandidates, configCreateNames)
}

// loadExplicit 只加载显式指定的配置文件：不存在或解析失败都直接报错，不创建任何新文件。
func loadExplicit(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("指定的配置文件不存在：%s", path)
		}
		return nil, fmt.Errorf("读取配置文件 %s 失败：%w", path, err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败：%w", path, err)
	}
	cfg.applyDefaults()
	return &Result{Config: cfg, Path: path}, nil
}

// loadConfig 按 candidates 顺序查找并加载配置文件：
//   - 找到且解析成功：使用该配置；
//   - 存在但解析/读取失败：记录警告并继续尝试下一个候选；
//   - 全部候选都不可用：尝试创建 createNames 中的默认配置文件；
//   - 创建目标已存在导致无法创建：返回错误。
func loadConfig(candidates, createNames []string) (*Result, error) {
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
		return &Result{Config: cfg, Path: name, Warnings: warnings}, nil
	}

	// 没有任何可加载的配置：创建默认配置文件。
	name, err := createDefaultConfig(createNames)
	if err != nil {
		if len(warnings) > 0 {
			return nil, fmt.Errorf("%v；且创建默认配置失败：%w", warnings[len(warnings)-1], err)
		}
		return nil, err
	}
	return &Result{Config: DefaultConfig(), Path: name, Created: true, Warnings: warnings}, nil
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
