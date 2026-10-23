package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
	Snaplen   int    `toml:"snaplen"`    // 内核层 BPF 每包复制到用户态的最大字节数；默认 256
	Protocol  string `toml:"protocol"`   // 内核层过滤器放行的协议：udp / tcp / all；默认 udp
}

// MemoryConfig 对应 [memory] 配置段：内存 / 资源控制。
type MemoryConfig struct {
	Limit     string `toml:"memory_limit"` // Go 堆内存软上限（如 "24MiB"）；留空表示不限制
	GCPercent *int   `toml:"gc_percent"`   // GC 目标百分比（GOGC 语义）；nil = 保持运行时默认（含 GOGC 环境变量）
	LowMemory bool   `toml:"low_memory"`   // 低内存模式：触发告警后清空对端列表且不再记录新对端
	PeerLimit *int   `toml:"peer_limit"`   // 单端口对端记录上限；nil = 用默认值，0 = 不限制
	MaxPorts  *int   `toml:"max_ports"`    // 单设备端口条目上限；nil = 用默认值，0 = 不限制
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

// SnaplenValue 返回内核层 BPF 实际复制到用户态的字节数（snaplen）。
//
// 默认 256B：解析只读以太网头 + IP 头 + 扩展头 + 4 字节端口，负载无需进用户态；
// 报文长度统计取内核记录的 tp_len（wireLen），不受截断影响。
// 传入 <= 0 时使用默认值；小于 64 会被抬到 64；大于 frame_size 会被压到 frame_size。
// 注意：若某个报文的传输层头落在 snaplen 之外（超长 IPv6 扩展头链等），该包会被跳过；
// 需要完整帧时把 snaplen 设为 frame_size 即回到不截断行为。
func (c CaptureConfig) SnaplenValue() int {
	frame, _, _ := c.RingParams()
	n := c.Snaplen
	if n <= 0 {
		n = defaultSnaplen
	}
	if n < minSnaplen {
		n = minSnaplen
	}
	if n > frame {
		n = frame
	}
	return n
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

// MaxPortsValue 返回生效的单设备端口条目上限：
//   - 未配置（nil）：默认 defaultMaxPorts；
//   - <=0：返回 0，表示不限制（关闭该功能）。
func (c *Config) MaxPortsValue() int {
	if c.Memory.MaxPorts == nil {
		return defaultMaxPorts
	}
	if *c.Memory.MaxPorts <= 0 {
		return 0
	}
	return *c.Memory.MaxPorts
}

// GCPercentValue 返回生效的 GC 目标百分比（对应 debug.SetGCPercent 的入参，GOGC 语义）：
//   - 未配置（nil）：返回 (0, nil)，表示保持运行时默认（含 GOGC 环境变量），调用方应跳过设置；
//   - 显式配置：须在 [gcPercentMin, gcPercentMax] 内，否则返回错误（<=0 含 -1 会禁用或退化 GC，
//     对长期驻留运行的检测工具危险，故拒绝）。
func (c *Config) GCPercentValue() (int, error) {
	if c.Memory.GCPercent == nil {
		return 0, nil
	}
	v := *c.Memory.GCPercent
	if v < gcPercentMin || v > gcPercentMax {
		return 0, fmt.Errorf("gc_percent 须在 %d~%d 之间，得到 %d（推荐 20~50）", gcPercentMin, gcPercentMax, v)
	}
	return v, nil
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

// FirewallConfig 对应 [firewall] 配置段（自动封禁 / 解封）：
// 公共项平铺，后端专用项各放入以该后端命名的子表
// （[firewall.hook] / [firewall.iptables] / [firewall.nftables]），只解析当前 backend 对应的子表。
type FirewallConfig struct {
	Enabled         bool                   `toml:"enabled"`           // 是否启用
	Backend         string                 `toml:"backend"`           // hook / iptables / nftables
	BanBoth         *bool                  `toml:"ban_both"`          // 是否同时封禁 IPv4/IPv6；默认 true
	BanActiveAlerts bool                   `toml:"ban_active_alerts"` // 启用/重载时把当前告警会话补发为封禁；默认 false
	Timeout         Duration               `toml:"timeout"`           // 单条命令执行超时
	Hook            FirewallHookConfig     `toml:"hook"`              // [firewall.hook]：hook 后端
	Iptables        FirewallIptablesConfig `toml:"iptables"`          // [firewall.iptables]：iptables 后端
	Nftables        FirewallNftablesConfig `toml:"nftables"`          // [firewall.nftables]：nftables 后端
}

// FirewallHookConfig 对应 [firewall.hook]：仅 backend = "hook" 时使用。
// 只配一条命令模板，由 {action} 区分动作（ban / unban），
// 占位符：{action} {mac} {ip} {port} {family} {proto}。
// ban_both=true 时对 v4 / v6 各执行一次（用 {family} 区分）；调用方按需自写 sh 包装分发。
type FirewallHookConfig struct {
	Cmd string `toml:"cmd"` // 命令模板，如 "my-hook {action} {mac} {port} {family} {proto}"
}

// FirewallIptablesConfig 对应 [firewall.iptables]：仅 backend = "iptables" 时使用。
// 留空时的默认链（FORWARD / INPUT）由 firewall 层按后端补齐。
type FirewallIptablesConfig struct {
	Chain      string `toml:"chain"`       // 端口封禁的跳转插入点（留空默认 FORWARD）
	InputChain string `toml:"input_chain"` // UPnP 拦截的跳转插入点（留空默认 INPUT）
	BanChain   string `toml:"ban_chain"`   // 端口封禁专用链名（留空默认 PCDN_DETECT）
	UPnPChain  string `toml:"upnp_chain"`  // UPnP 拦截专用链名（留空默认 PCDN_DETECT_UPNP）
}

// FirewallNftablesConfig 对应 [firewall.nftables]：仅 backend = "nftables" 时使用。
// 留空时的默认钩子（prerouting / input）由 firewall 层按后端补齐。
type FirewallNftablesConfig struct {
	Table     string   `toml:"table"`      // 表名（端口封禁链名与表名一致）
	Set       string   `toml:"set"`        // 集合名前缀（实际使用 <set>_<family>_<proto>）
	Hook      string   `toml:"hook"`       // 端口封禁链的钩子（留空默认 prerouting）
	InputHook string   `toml:"input_hook"` // UPnP 拦截专用链的钩子（留空默认 input，「进入路由器」方向）
	BanTTL    Duration `toml:"ban_ttl"`    // 封禁元素超时（如 "30m"）；0/留空 = 不设置（进程死后规则不会自动过期）
}

// BanBothEnabled 返回是否同时封禁 IPv4 与 IPv6（未配置时默认 true）。
func (c FirewallConfig) BanBothEnabled() bool {
	return c.BanBoth == nil || *c.BanBoth
}

// FullBanConfig 对应独立的 [full_ban] 配置段：在端口封禁之上叠加的
// 「全 UDP 端口封禁」模式（设备级）。依赖 [firewall] 启用（复用其后端）。
type FullBanConfig struct {
	Mode      string            `toml:"mode"`      // off / on / device；默认 off
	Threshold int               `toml:"threshold"` // 触发阈值：被封禁的不同端口数达到该值
	Allow     []any             `toml:"allow"`     // 放行的 UDP 端口（整数或表达式字符串）；为空时用内置常用端口
	Hook      FullBanHookConfig `toml:"hook"`      // [full_ban.hook]：仅 hook 后端使用
}

// FullBanHookConfig 对应 [full_ban.hook]：仅 hook 后端使用。
// 只配一条命令模板，由 {action} 区分动作（ban / unban）；对 v4/v6 各执行一次。
// 占位符：{action} {mac} {ip} {family} {ports}
// （{ip} 为设备 IP，仅当地址族与 {family} 一致时填入，否则为空；{ports} 为放行端口逗号列表）。
type FullBanHookConfig struct {
	Cmd string `toml:"cmd"` // 命令模板，如 "my-fullban {action} {mac} {ip} {family} {ports}"
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

// UPnPConfig 对应独立的 [upnp] 配置段：拦截设备向路由器发起的 UPnP 请求
// （SSDP 发现 + HTTP 控制），依赖 [firewall] 启用（复用其后端）。
type UPnPConfig struct {
	Mode  string         `toml:"mode"`  // off / on / device；默认 off
	Ports []any          `toml:"ports"` // 拦截的 UPnP 目的端口（整数或表达式字符串）；为空时用内置端口
	Hook  UPnPHookConfig `toml:"hook"`  // [upnp.hook]：仅 hook 后端使用
}

// UPnPHookConfig 对应 [upnp.hook]：仅 hook 后端使用。
// 只配一条命令模板，由 {action} 区分动作；对 v4/v6 各执行一次。
// 占位符：{action} {mac} {ip} {family} {ports}
// （{ip} 为设备已知 IP，仅当地址族与 {family} 一致时填入，否则为空；{ports} 为端口逗号列表）。
// 动作取值（调用方按需自写 sh 包装分发）：
//   - ban / unban：黑名单模式按设备拦截 / 解除；
//   - block-all / unblock-all：白名单模式拦截 / 解除全部（{mac} / {ip} 为空）；
//   - allow / disallow：白名单模式放行 / 取消放行某设备。
type UPnPHookConfig struct {
	Cmd string `toml:"cmd"` // 命令模板，如 "my-upnp {action} {mac} {ip} {family} {ports}"
}

// UPnPMode 返回规范化的 UPnP 拦截模式（未配置时视为 off）。
func (c UPnPConfig) UPnPMode() string {
	if c.Mode == "" {
		return UPnPOff
	}
	return c.Mode
}

// UPnPEnabled 返回是否启用 UPnP 拦截（mode != off）。
func (c UPnPConfig) UPnPEnabled() bool {
	return c.UPnPMode() != UPnPOff
}

// HTTPConfig 对应 [http] 配置段：可选的 HTTP API（运行时状态读取 + 动作 + 重载）。
// 默认仅监听回环地址；token 非空时要求 Bearer 鉴权。
type HTTPConfig struct {
	Enabled       bool   `toml:"enabled"`         // 是否启用
	Listen        string `toml:"listen"`          // 监听地址，留空默认 127.0.0.1:8080
	Token         string `toml:"token"`           // Bearer 令牌；非空时校验 Authorization
	DeviceIPLimit *int   `toml:"device_ip_limit"` // /peers 每个端口返回的对端 IP 上限；nil/<=0 用默认 200
	StateDir      string `toml:"state_dir"`       // 重启继承用状态文件目录；留空为系统临时目录
}

// ListenAddr 返回生效的监听地址（未配置时用默认）。
func (c HTTPConfig) ListenAddr() string {
	if strings.TrimSpace(c.Listen) == "" {
		return defaultHTTPListen
	}
	return c.Listen
}

// NoToken 表示显式关闭鉴权（token = "allow-no-token"）。
func (c HTTPConfig) NoToken() bool {
	return strings.TrimSpace(c.Token) == TokenAllowNoToken
}

// BearerToken 返回实际生效的 Bearer 令牌：token = "allow-no-token" 时返回空串（表示不鉴权）。
func (c HTTPConfig) BearerToken() string {
	if c.NoToken() {
		return ""
	}
	return c.Token
}

// DeviceIPLimitValue 返回生效的 /peers 对端 IP 上限（未配置或 <=0 时用默认值）。
func (c HTTPConfig) DeviceIPLimitValue() int {
	if c.DeviceIPLimit == nil || *c.DeviceIPLimit <= 0 {
		return defaultDeviceIPLimit
	}
	return *c.DeviceIPLimit
}

// StateDirPath 返回状态文件所在目录（未配置时用系统临时目录）。
func (c HTTPConfig) StateDirPath() string {
	if strings.TrimSpace(c.StateDir) == "" {
		return os.TempDir()
	}
	return c.StateDir
}

// StateFilePath 返回状态文件的完整路径。
func (c HTTPConfig) StateFilePath() string {
	return filepath.Join(c.StateDirPath(), stateFileName)
}

// Config 对应配置文件内容，按功能分块。
type Config struct {
	Detect   DetectConfig   `toml:"detect"`   // 检测阈值与时间参数
	Capture  CaptureConfig  `toml:"capture"`  // 抓包网卡与环形缓冲
	Memory   MemoryConfig   `toml:"memory"`   // 内存 / 资源控制
	Log      LogConfig      `toml:"log"`      // 日志时区与展示
	HTTP     HTTPConfig     `toml:"http"`     // HTTP API（运行时状态读取 / 动作 / 重载）
	Filter   FilterConfig   `toml:"filter"`   // 黑白名单
	Firewall FirewallConfig `toml:"firewall"` // 防火墙对接
	FullBan  FullBanConfig  `toml:"full_ban"` // 全 UDP 端口封禁模式（独立配置块）
	UPnP     UPnPConfig     `toml:"upnp"`     // UPnP 拦截（独立配置块）
}

// listEntry 是名单中的一条。用结构体承载便于将来按 MAC 扩展更多字段
// （如独立阈值、窗口等）；目前支持 mac / ports / enabled / full_ban / upnp。
type listEntry struct {
	MAC     string `toml:"mac"`      // 设备 MAC（必填）
	Ports   []any  `toml:"ports"`    // 端口数组：整数或表达式字符串；留空表示全部端口
	Enabled *bool  `toml:"enabled"`  // 该条是否生效，默认 true
	FullBan *bool  `toml:"full_ban"` // 是否为该设备启用全 UDP 端口封禁（full_ban = "device" 时使用）
	UPnP    *bool  `toml:"upnp"`     // 是否为该设备启用 UPnP 拦截（upnp = "device" 时使用）
}

// isEnabled 返回该条是否生效（未设置 enabled 视为 true）。
func (e listEntry) isEnabled() bool {
	return e.Enabled == nil || *e.Enabled
}
