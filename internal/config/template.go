package config

// defaultConfigTemplate 是自动生成的配置模板（TOML，带注释，便于使用者修改）。
// 它同时是配置项的权威说明（README 直接指向本文件）：首次启动未找到任何可用配置时，
// 程序会把该模板原样写入当前工作目录的 pcdn-detect.toml。
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
# 支持 "16MiB"、"24M"、纯字节数等写法；未配置（保持注释）时不设置软上限，由运行时自行决定
# （也可改用环境变量 GOMEMLIMIT，该变量由 Go 运行时原生识别）。
# 建议设为设备可用内存的一半左右，例如 128MB 内存的路由器可设 "32MiB"；设置时请预留
# mmap 抓包环形缓冲（默认 256KiB）+ 2~3MiB 余量（memory_limit 只统计 Go 堆，不含环形缓冲）。
# memory_limit = "32MiB"

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
# 日志输出等级（从低到高）：debug / info / warn / error，低于该等级的日志不再输出。
#   warn（默认）：只输出警告与错误；
#   info：额外输出检测告警（疑似 / 持续产生 PCDN 行为、行为结束）与封禁 / 解封等业务事件；
#   debug：额外输出调试信息。
# 可用 SIGHUP 或 POST /api/v1/reload 热更新。
level = "warn"

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
