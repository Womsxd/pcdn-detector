// Package config 负责加载与校验 TOML 配置，并定义各项配置的默认值与取值规范。
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
# 默认 65536 * 4 = 256KiB；若抓包出现丢包可适当增大 num_blocks（如 8 = 512KiB）。
#   frame_size  单个帧上限（字节），须能整除 block_size；默认 2048；
#   block_size  每个块大小（字节），须为页大小(4096)与 frame_size 的整数倍；
#   num_blocks  块数量，至少为 1。
# snaplen 为内核层 BPF 每包复制到用户态的最大字节数（默认 256，只需头部）：
#   解析只用到以太网 + IP + 扩展头 + 4 字节端口；调大可覆盖更长的 IPv6 扩展头链，
#   设为 frame_size 即不截断（旧行为，但内核复制量与内存带宽更高）。
frame_size = 2048
block_size = 65536
num_blocks = 4
snaplen = 256

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
# 建议设为设备可用内存的一半左右，例如 128MB 内存的路由器可设 "32MiB"；设置时请预留
# mmap 抓包环形缓冲（默认 2MiB）+ 2~3MiB 余量（memory_limit 只统计 Go 堆，不含环形缓冲）。
memory_limit = ""

# GC 目标百分比（GOGC 语义，对应运行时的 debug.SetGCPercent）：
#   堆内新增数据达到「存活堆 × gc_percent/100」时触发 GC。
#   未配置（保持注释）时用运行时默认（GOGC=100，即堆翻倍才触发），也尊重环境变量 GOGC。
#   低内存设备可设为 20~50：常驻堆峰值更低，代价是 GC 更频繁、CPU 占用略升。
#   与 memory_limit 不冲突：堆逼近软上限时由软上限追加收紧，远离上限时由本项决定。
# 取值范围 1~1000（推荐 20~50）；-1 会关闭 GC，不支持。
# gc_percent = 30

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

# 单设备端口条目上限：同一设备（MAC）同时跟踪的「本地端口 + 协议 + 地址族」条目数上限，
# 防止目的端口扫描、QUIC / TCP 短连接产生的大量临时端口把端口表撑爆（每条约 174 字节，
# IPv6 约 230 字节）。达到上限时会按「最接近过期 + 同档内对端数最少」批量提前过期 10% 的
# 端口，为新端口腾出位置。取值说明：
#   - 省略（保持注释）：默认 512（约 90KiB/设备，低内存设备可再调小）；
#   - 0：不限制（关闭该功能）。
# 告警中的端口不参与提前过期；若全部端口都在告警中，则新端口不建立、该端口的流量不再累计
# （日志会提示，可通过 /api/v1/devices 的 port_drops 观察）。
# max_ports = 512

# ===== 日志展示 =====
[log]
# 日志时区：IANA 名称（如 Asia/Shanghai）或 POSIX 串（如 CST-8）；留空表示自动读取系统时区
timezone = ""

# 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC（MAC / IPv6 保留前两段与最后一段，如
# 60:21:...:23、2408:8240:...:b2a3；IPv4 保留首尾，中间两段写作 *，如 112.*.*.51），
# 便于对外分享日志；设备外连的远端对端地址不受影响。
# 内网 IPv4（如 192.168.x.x）不会被隐藏。
hide_address = false

# ===== HTTP API（运行时状态读取 / 动作 / 重载）=====
# 可选的本机管理接口：读取运行时状态、手动解封、重载配置。默认关闭。
# 注：配置热重载不依赖本接口——SIGHUP（kill -HUP <pid>；OpenWrt 的 /etc/init.d reload 默认
# 发送该信号）始终可用。
[http]
# 是否启用 HTTP API
enabled = false

# 监听地址。默认仅监听回环地址（127.0.0.1），本机可访问；
# 若要监听其它地址（如 0.0.0.0:8080），必须同时设置下面的 token，否则启动会被拒绝
# （或显式设 token = "allow-no-token" 关闭鉴权）。
listen = "127.0.0.1:8080"

# Bearer 令牌：非空时，所有请求须带 Authorization: Bearer <token>。
# 特殊值 "allow-no-token" 表示显式关闭鉴权（允许无 token 访问，并允许绑定非回环地址）。
token = ""

# /api/v1/peers 每次最多返回的对端 IP 数量（防止单次响应构造过大内存）；默认 200。
device_ip_limit = 200

# 重启继承用的状态文件目录（二进制临时文件，含 MAC / IP，权限 0600）；留空为系统临时目录（如 /tmp）。
# state_dir = ""

# ===== 黑白名单（按设备 MAC 过滤）=====
[filter]
# list_mode 选择模式（留空默认白名单）：
#   "whitelist" = whitelist 名单内命中的设备（或指定端口）不检测，其余照常检测（默认；名单为空即检测全部设备）
#   "blacklist" = 只检测 blacklist 名单内的设备，其余不检测
list_mode = "whitelist"

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
# upnp = true                      # 为该设备启用 UPnP 拦截（[upnp] mode = "device" 时使用）
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
# 封禁地址族：true（默认）= 同时封禁设备的 IPv4 与 IPv6；
# false = 按触发到的地址族单独封禁（v4 与 v6 各自独立封禁 / 解封）
# ban_both = true
#
# 补发封禁（默认关闭）：启用防火墙 / reload 时，把检测层当前**已处于告警中**的端口直接纳入封禁，
# 不再等下一轮触发。适用于「启动时防火墙关闭、运行中 reload 启用」，或状态文件只恢复了告警
# 会话而没有封禁的场景；补发是幂等的，不会重复下发已存在的规则。
# ban_active_alerts = false
#
# 单条命令执行超时
# timeout = "5s"
#
# ---- 后端专用项按后端分块，只解析当前 backend 对应的块（其余块可保留备用）----
#
# backend = "hook"：自定义命令，单条模板用 {action} 区分动作（ban / unban）
# 占位符：{action} {mac} {ip} {port} {family} {proto}；ban_both=true 时对 v4/v6 各执行一次（{family} 区分）
# [firewall.hook]
# cmd = "my-hook {action} {mac} {ip} {port} {family} {proto}"
#
# backend = "iptables"：iptables 与 ip6tables 的专用链 PCDN_DETECT / PCDN_DETECT_UPNP
# 按源 MAC + 触发协议 + 源端口丢弃；下面的 chain / input_chain 只是跳转插入点
# （启动时会清空并重建专用链，可清理上次进程被 kill 后残留的封禁，不影响用户自己的规则）
# [firewall.iptables]
# chain = "FORWARD"                # 端口封禁的跳转插入点（默认 FORWARD）
# input_chain = "INPUT"            # UPnP 拦截的跳转插入点（默认 INPUT）
# ban_chain = "PCDN_DETECT"        # 端口封禁专用链名（自定义时请勿与 chain / input_chain 重名）
# upnp_chain = "PCDN_DETECT_UPNP"  # UPnP 拦截专用链名（同上）
#
# backend = "nftables"：bridge 族的指定钩子按源 MAC + 触发协议 + 源端口丢弃（链名固定与表名一致）
# （表/集合/钩子可自定义；集合按「地址族 + 协议」拆分为 <set>_<family>_<proto>，如 banned_v4_udp）
# [firewall.nftables]
# table = "pcdn_detect"
# set = "banned"                   # 实际使用 <set>_v4_udp / _v4_tcp / _v6_udp / _v6_tcp
# hook = "prerouting"              # prerouting（默认）/ input / forward / output / postrouting；PCDN 为路由流量，建议保持 prerouting
# input_hook = "input"             # UPnP 拦截专用链的钩子（默认 input，「进入路由器」方向）；可选同 hook 的值
#
# 封禁元素超时（默认不设置）：设置后端口封禁 / 全端口封禁的集合元素带 timeout，Blocker 会按
# TTL/3 周期重新 add 续期；进程被 SIGKILL / OOM 杀死后由内核自动过期，不再依赖下次启动清理。
# 注意：需要内核 nftables 集合支持 timeout（约 4.8+），且重复 add 能刷新超时；若刷新失败，
# 封禁可能在告警结束前提前失效（fail-open），请按实际内核验证后再启用。
# ban_ttl = "30m"

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
# hook 后端专用：单条命令模板，{action} 为 ban / unban，对 v4/v6 各执行一次（{family} 区分）；
# 占位符 {action} {mac} {ip} {family} {ports}（{ip} 与 {family} 匹配时填入，{ports} 为放行端口逗号列表）
# [full_ban.hook]
# cmd = ""

# ===== UPnP 拦截（独立配置块）=====
# 拦截设备向路由器发起的 UPnP 请求（SSDP 发现 + HTTP 控制），依赖 [firewall] 启用（复用其后端）。
# 拦截按「源 MAC」生效，对该设备的 IPv4 与 IPv6 同时起作用（目的端口见 ports）。
# 拦截所在的链/钩子由 [firewall.iptables] input_chain 与 [firewall.nftables] input_hook 决定
# （分别默认 INPUT / input，即「进入路由器」方向；特殊场景可改）。iptables 下 input_chain 只是
# 跳转插入点，规则实际写入专用链 PCDN_DETECT_UPNP。
#
# 拦截范围随 [filter] list_mode 变化：
#   黑名单模式 = 仅拦截名单内设备；白名单模式 = 拦截全部进入路由器的 UPnP，仅放行名单内设备。
# [upnp]
# mode = "off"                    # off（默认）/ on（名单内全部设备）/ device（仅名单中标 upnp = true 的设备）
#
# 拦截的 UPnP 目的端口（元素可为整数或表达式字符串）。
# 留空（或删除该行）时使用内置端口：[1900, 5000]（SSDP 发现 / miniupnpd HTTP 控制）。
# 显式配置时以其为准（不叠加内置端口），例如：
# ports = [1900, 5000]
#
# hook 后端专用：单条命令模板，{action} 区分动作，对 v4/v6 各执行一次（{family} 区分）。
# 占位符 {action} {mac} {ip} {family} {ports}（{ip} 与 {family} 匹配时填入，{ports} 如 1900,5000）。
# 动作：ban / unban（黑名单按设备拦截 / 解除）、block-all / unblock-all（白名单拦截 / 解除全部）、
#       allow / disallow（白名单放行 / 取消放行某设备）。调用方按需自写 sh 包装分发。
# [upnp.hook]
# cmd = ""
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
			Snaplen:   defaultSnaplen,
			Protocol:  ProtoModeUDP,
		},
		Filter: FilterConfig{ListMode: filter.ModeWhitelist},
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
	c.Capture.Snaplen = c.Capture.SnaplenValue() // 未配置/非法时回落到默认 256，超过 frame_size 时截到 frame_size
	// 全端口封禁模式：未配置时默认 off；阈值非法时回退默认值。
	if c.FullBan.Mode == "" {
		c.FullBan.Mode = FullBanOff
	}
	if c.FullBan.Threshold <= 0 {
		c.FullBan.Threshold = defaultFullBanThreshold
	}
	// UPnP 拦截模式：未配置时默认 off。
	if c.UPnP.Mode == "" {
		c.UPnP.Mode = UPnPOff
	}
	// HTTP API 监听地址：未配置时默认回环地址（其余 HTTP 项由 HTTPConfig 方法兜底）。
	if strings.TrimSpace(c.HTTP.Listen) == "" {
		c.HTTP.Listen = defaultHTTPListen
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
	m, err := parseListMode(cfg.Filter.ListMode)
	if err != nil {
		return nil, err
	}
	cfg.Filter.ListMode = m
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
	up, err := ParseUPnPMode(cfg.UPnP.Mode)
	if err != nil {
		return nil, err
	}
	cfg.UPnP.Mode = up
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

// LoadConfigStrict 只加载已存在的配置文件：显式指定时仅用该文件，否则按默认候选顺序查找。
// 找不到或解析失败都返回错误，绝不创建默认配置（供 --test-config 校验配置文件使用）。
func LoadConfigStrict(explicitPath string, hasExplicit bool) (*Result, error) {
	if hasExplicit {
		return loadExplicit(explicitPath)
	}
	return loadConfig(configCandidates, nil)
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

	// createNames 为空表示「只校验、不创建」（见 LoadConfigStrict）。
	if len(createNames) == 0 {
		if len(warnings) > 0 {
			return nil, fmt.Errorf("没有可用的配置文件：%s", strings.Join(warnings, "；"))
		}
		return nil, fmt.Errorf("未找到配置文件（已查找：%s），请用 -c/--config 指定路径", strings.Join(candidates, "、"))
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
