package config

import "time"

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

	// 单设备端口条目上限的默认取值：防止目的端口扫描、QUIC / TCP 短连接产生的大量临时
	// 端口把端口表撑爆。显式设为 0 表示不限制（关闭该功能）。
	defaultMaxPorts = 512

	// GC 目标百分比（配置项 [memory] gc_percent，对应 debug.SetGCPercent / GOGC 语义）的合法范围。
	// 未配置时不干预运行时默认（含 GOGC 环境变量）；<=0（含 -1）会禁用或退化 GC，对常驻工具危险，故拒绝。
	gcPercentMin = 1
	gcPercentMax = 1000

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

	// UPnP 拦截模式（配置项 [upnp] mode）取值。
	UPnPOff    = "off"    // 默认：关闭
	UPnPOn     = "on"     // 对黑名单内的全部设备启用
	UPnPDevice = "device" // 仅对 filter 中标记 upnp = true 的设备启用

	// AF_PACKET 内核环形缓冲默认划分：总内存 = block_size * num_blocks = 256KiB。
	// 配合内核层 BPF 的 snaplen 截断（默认每包只复制 256B），缓冲里能装下的包数与
	// 旧默认（2MiB、整帧复制）大致相当，但固定内存与内核复制量都小一个量级。
	defaultFrameSize = 2048
	defaultBlockSize = 65536
	defaultNumBlocks = 4

	// defaultSnaplen 是内核层 BPF 的返回值：每个报文最多复制到用户态的字节数。
	// 解析只需要以太网头 + IP 头 + 扩展头 + 4 字节端口，256B 足够覆盖常见 IPv6 扩展头链。
	// 想要完整帧（旧行为）可显式把 snaplen 设为 frame_size。
	defaultSnaplen = 256
	minSnaplen     = 64

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

// defaultUPnPPorts 是 UPnP 拦截默认覆盖的目的端口：SSDP 发现（UDP 1900）与
// miniupnpd HTTP 控制端口（默认 5000）。仅在 [upnp] ports 为空（未配置 / 空数组）时生效；
// 一旦显式配置则以其为准（不叠加）。
var defaultUPnPPorts = []uint16{1900, 5000}

// HTTP API（配置项 [http]）的默认值。
const (
	defaultHTTPListen    = "127.0.0.1:8080"    // 默认仅监听回环地址
	defaultDeviceIPLimit = 200                 // /peers 每个端口返回的对端 IP 上限
	stateFileName        = "pcdn-detect.state" // 重启继承用状态文件名（二进制）
)

// TokenAllowNoToken 是 [http] token 的特殊取值：显式**关闭鉴权**。
// 设为该值时不校验 Authorization，且允许绑定非回环地址（即使未配置其它 token）。
const TokenAllowNoToken = "allow-no-token"
