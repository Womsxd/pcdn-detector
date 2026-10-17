# pcdn-detect — P2P CDN 行为检测工具

在 OpenWrt / Linux 路由器上运行，监听指定网卡，对局域网设备的流量进行抓包分析。
当某台设备（MAC）在**指定时长**内、通过**同一个本地端口**连接了**超过阈值数量**的不同
远端公网 IP 时，判定其疑似存在 PCDN 行为并输出告警。

## 工作原理

1. 启动时读取配置文件（见下「配置文件」），命令行参数可覆盖；指定网卡、触发次数（阈值）、检测时长等。
2. 使用 AF_PACKET（Linux 内核环形缓冲）对该网卡抓包——功能等价于 pcap，
   但为**纯 Go 实现、无 CGO / 无 libpcap 依赖**，可交叉编译为静态文件，便于在 OpenWrt 部署。
   抓包 socket 附带内核层 BPF 过滤器，**默认只放行 UDP**（可用 `-P` / `--protocol` 或 `[capture] protocol` 设为 `udp` / `tcp` / `all`），
   ARP / STP / ICMP / ICMPv6 等无关报文在进入用户态之前即被丢弃。
3. 解析以太网 / IPv4 / IPv6 / TCP / UDP 头部，识别「局域网设备 <-> 公网对端」的流量，
   按 `设备MAC + 本地端口 + 传输层协议` 分别统计在滑动窗口 `时长` 内出现的不同远端公网 IP 数量。
4. 数量达到 `触发次数` 即输出「疑似产生PCDN行为」告警。随后进入**持续期**（默认 10 分钟，
   可配置）：期间**只要该端口仍有流量（任意对端，无论新旧）**就刷新持续期计时器（即滑动续期），
   不再要求窗口内数量达到阈值；若出现**新的对端 IP**（哪怕只有 1 个）则额外输出
   「持续产生PCDN行为」；若持续 `-alert-duration` 时长内都没有**任何流量**，
   则输出「PCDN行为结束」并结束本轮，之后可重新触发。
5. 若配置了**黑白名单**，则按设备 MAC（黑/白名单均可再限定端口）过滤需要检测的设备，详见 [黑白名单](docs/filter.md)。
6. 若启用了**防火墙对接**，首次告警时自动封禁该设备在该端口上的流量（封禁协议随 `[capture] protocol` 变化：`udp` 仅 UDP、`tcp` 仅 TCP、`all` 为 UDP+TCP），「PCDN行为结束」时自动解封，详见 [防火墙对接](docs/firewall.md)。
7. 若启用了**全 UDP 端口封禁模式**（独立的 `[full_ban]` 配置块），某设备**被封禁的不同端口数**达到阈值后，会进一步对该设备**封禁全部 UDP 端口**（仅放行 DNS / NTP / DHCP 等常用端口及自定义放行端口），被封禁端口全部解除后自动解除，详见 [防火墙对接](docs/firewall.md#全-udp-端口封禁模式full_ban)。
8. 若启用了 **UPnP 拦截**（独立的 `[upnp]` 配置块），会拦截**设备向路由器发起的 UPnP 请求**（SSDP 发现 + HTTP 控制）：**黑名单模式**下仅拦截名单内设备；**白名单模式**下拦截全部、仅放行名单内设备；程序退出时自动解除，详见 [UPnP 拦截](docs/upnp.md)。

> PCDN 节点通常在同一端口上与大量对端建立连接，因此「单端口 + 大量对端 IP」是典型特征。
> 该工具适合在 **LAN 侧网桥接口（如 `br-lan`）** 上运行，才能看到各设备的 MAC。

### IPv6 支持

- **完整支持 IPv6**：解析 IPv6 基础头，并会跳过 Hop-by-Hop、Routing、Fragment、AH、
  Destination Options、Mobility 等扩展头，定位到 TCP/UDP。
- 设备归属判断基于**网卡自身所在网段**（IPv4 子网 + IPv6 前缀）而非「公网/内网」区分，
  因此在 IPv6 全局地址（无 NAT，设备与对端都是公网地址）场景下同样能正确识别设备与远端对端。
- 链路本地（`fe80::/10`）、ULA（`fc00::/7`）、组播、环回等不作为有效远端对端统计。
- 同一设备同时拥有 IPv4 与 IPv6 地址时，按**端口 + 地址族**分别统计，
  告警中输出的设备 IP 始终与该端口流量所属地址族一致。

## 编译

需要 Go 1.21+。

```bash
# 本地构建
make build

# OpenWrt 交叉编译（产出静态文件到 bin/）
make mipsle   # ramips / mt7621 (mipsel_24kc)
make mips     # ar71xx / ath79 (mips_24kc)
make arm      # armv7
make arm64    # armv8 / aarch64

# 精简版：不编译 HTTP API（体积更小，要求配置里 [http] enabled = false）
make nohttp              # 全架构，产物名为 bin/*-nohttp
make TAGS=nohttp mipsle  # 只编某个架构
```

`nohttp` 构建使用 `-tags nohttp` 把 `internal/httpapi` 替换为空壳，不链接 `internal/minihttp`
与路由/序列化代码（mipsle 可再小约 0.8 MB）。若该二进制加载到 `[http] enabled = true` 的配置，
会直接报错退出并提示改用常规构建。

不确定路由器架构时，可在路由器上执行 `cat /proc/cpuinfo` / `uname -m` 判断，
或使用 `opkg print-architecture` 查看（如 `mipsel_24kc` 对应 `make mipsle`）。

### 项目结构

```
cmd/pcdn-detect/   程序入口（命令行解析、装配各组件）
internal/config/   配置加载与校验、默认值、内存大小解析
internal/capture/  AF_PACKET 抓包与报文解析、内核 BPF 过滤
internal/detector/ 滑动窗口统计与告警（map 收缩、内存优化）
internal/filter/   黑白名单过滤
internal/firewall/ 防火墙对接（hook / iptables / nftables）
internal/blocker/  告警事件到封禁 / 解封的协调
internal/httpapi/  HTTP API（运行时状态读取、手动解封、重载配置）
internal/state/    重启继承用的运行时状态（二进制序列化）
internal/netutil/  共享的网络基础类型（MAC、协议号、公网地址判定）
internal/util/     日志展示格式化（字节数量、设备地址掩码）
internal/tz/       日志时区解析
```

## 部署与运行

抓包需要 `CAP_NET_RAW`，请在 **root** 或具备相应能力的环境下运行。

```bash
# 上传到路由器
scp bin/pcdn-detect-mipsle root@192.168.1.1:/usr/bin/pcdn-detect
ssh root@192.168.1.1 chmod +x /usr/bin/pcdn-detect

# 运行：监听 br-lan，60 秒内同一端口出现 20 个不同对端 IP 即告警
/usr/bin/pcdn-detect -i br-lan -n 20 -t 60s
```

### 参数

| 短 / 长 | 默认值 | 说明 |
| --- | --- | --- |
| `-i` / `--interface` | 空（必填） | 监听的网卡名称，如 `br-lan`、`br0`、`eth0` |
| `-n` / `--count` | `20` | 触发次数：时长内同一设备同一端口的**不同远端公网 IP** 数量阈值 |
| `-t` / `--window` | `60s` | 检测时长（滑动窗口），支持 `30s`、`5m`、`1h` 等 |
| `-a` / `--alert-duration` | `10m` | 持续提示时长：期间只要端口仍有流量（无论新旧对端）就刷新计时器，超过该时长没有任何流量则输出「PCDN行为结束」并静默；支持 `5m`、`30m` 等 |
| `-p` / `--promisc` | `true` | 是否开启混杂模式 |
| `-s` / `--interval` | `2s` | 检测扫描间隔 |
| `-z` / `--timezone` | 空 | 日志时区，支持 IANA 名称（`Asia/Shanghai`）或 POSIX 串（`CST-8`）；默认自动读取 |
| `-H` / `--hide-address` | `false` | 隐私模式：隐藏设备自身的 IPv6 / 公网地址与 MAC（保留前两段与最后一段），远端对端不受影响 |
| `-L` / `--low-memory` | `false` | 低内存模式：端口触发告警后清空对端列表且不再记录新对端，仅保留触发状态 |
| `--peer-limit`（无短选项） | `max(1000, 阈值×10)`，低内存模式下为 `阈值` | 单端口对端记录上限；达到后不再记录该端口的新对端 IP；`0` 表示不限制，低于阈值时自动提升为阈值 |
| `-P` / `--protocol` | `udp` | 抓包协议：`udp`（仅 UDP）/ `tcp`（仅 TCP）/ `all`（UDP+TCP），大小写不敏感 |
| `-c` / `--config` | 空 | 指定配置文件路径（默认按候选顺序查找） |

> 短形式（`-x`）与完整形式（`--xxx`）完全等价，可混用。
> 上表的默认值即配置文件中的默认值；实际取值优先级为 **命令行参数 > 配置文件 > 内置默认值**。

### 配置文件

配置采用 **TOML** 格式（使用 `github.com/BurntSushi/toml`）。
启动时会**按顺序**在**当前工作目录**查找并读取下列文件，取**第一个能成功解析**的作为配置：

1. `config.toml`
2. `pcdn-detect.toml`

- 前一个文件**不存在**，或存在但**读取/解析失败**时，会自动尝试下一个（失败原因以「警告」形式记录到日志）。
- 若以上文件**全部不可用**，则自动创建 `pcdn-detect.toml`；
  若该文件已存在导致无法创建，则**报错退出**。
- 用 `-c <路径>` / `--config <路径>` 可**显式指定**配置文件：此时**只读取该文件**，不再走候选顺序，
  也**不会自动创建**——文件不存在或解析失败都会直接**报错退出**。
- **命令行参数优先于配置文件**：显式指定的参数会覆盖文件中的同名配置，未指定则使用文件中的值。

配置按功能分块（`[detect]` / `[capture]` / `[memory]` / `[log]` / `[http]` / `[filter]` / `[firewall]` / `[full_ban]` / `[upnp]`），
生成的配置文件示例（可直接编辑）：

```toml
# 以 # 开头的行为注释；配置按功能分块

[detect]                       # 检测阈值与时间参数
threshold = 20                 # 触发阈值：窗口内同一设备同一端口的不同远端公网 IP 数
window = "60s"                 # 检测时长（滑动窗口）
alert_duration = "10m"         # 持续提示时长
interval = "2s"                # 检测扫描间隔

[capture]                      # 抓包
interface = "br-lan"           # 网卡名称（必填）
promisc = true                 # 是否开启混杂模式
frame_size = 65536             # 抓包环形缓冲：总内存 = block_size * num_blocks（默认 2MiB，适合低内存设备）
block_size = 262144
num_blocks = 8
protocol = "udp"               # 内核层过滤器放行协议：udp（默认）/ tcp / all

[memory]                       # 内存 / 资源控制
memory_limit = ""              # Go 堆内存软上限（如 "24MiB"），留空表示不限制；低内存设备建议设置
# gc_percent = 30              # GC 目标百分比（GOGC 语义）：1~1000，推荐 20~50；省略则用运行时默认（100）
low_memory = false             # 低内存模式：端口触发告警后清空对端列表且不再记录新对端，仅保留触发状态
# peer_limit = 1000           # 单端口对端记录上限；省略时默认 max(1000, 阈值×10)（低内存模式下为阈值）；0 = 不限制，低于阈值时自动提升为阈值

[log]                          # 日志展示
timezone = "Asia/Shanghai"     # 日志时区，留空表示自动读取系统时区
hide_address = false           # 隐私模式：隐藏设备自身的 IPv6/公网地址与 MAC

[http]                         # HTTP API（运行时状态读取 / 动作 / 重载），默认关闭
enabled = false                # 是否启用
listen = "127.0.0.1:8080"      # 监听地址；绑定非回环地址时必须设置 token
token = ""                     # Bearer 令牌；非空时要求 Authorization: Bearer <token>；"allow-no-token" = 显式关闭鉴权
device_ip_limit = 200          # /api/v1/devices 每个端口最多返回的对端 IP 数
# state_dir = ""               # 重启继承用状态文件目录（二进制）；留空为系统临时目录（如 /tmp）

[filter]                       # 黑白名单（按设备 MAC 过滤）
list_mode = "whitelist"        # 留空默认 whitelist；blacklist / whitelist
# [[filter.blacklist]]         # 黑名单条目（省略 ports = 全部端口；指定 ports 则只检测这些端口，范围不足可能漏检）
# mac = "aa:bb:cc:dd:ee:ff"
# [[filter.whitelist]]         # 白名单条目（省略 ports = 全部端口）
# mac = "11:22:33:44:55:66"
# ports = [40000, 40001]

[upnp]                         # UPnP 拦截（依赖 [firewall] 启用）
mode = ""                      # 留空 = 不启用；on（名单内全部设备）/ device（仅名单中标 upnp = true 的设备）
# ports = [1900, 5000]         # 拦截的 UPnP 目的端口；留空用内置 [1900, 5000]（SSDP / HTTP 控制）
```

- 时长字段支持字符串（`"60s"`、`"5m"`、`"1h"`）或整数（按秒）。
- 出现**未知配置项**或 TOML 语法 / 类型错误时，该文件视为解析失败（按上述规则回退）。

> 配置文件相对**当前工作目录**定位。作为 procd 服务运行时（默认工作目录为 `/`），
> 请在启动命令中先 `cd` 到配置所在目录，或把配置放到该目录。

## 进阶配置

以下为按需查阅的详细配置说明，初次使用可按上文默认值直接运行：

- [内存占用与低内存优化](docs/memory.md)：内核抓包缓冲、BPF 过滤、`memory_limit` /
  `gc_percent` / `low_memory` / `peer_limit` 等内存控制项。
- [黑白名单](docs/filter.md)：`[filter]` 按设备 MAC（可限定端口）过滤检测范围。
- [防火墙对接](docs/firewall.md)：`[firewall]` 自动封禁 / 解封（hook / iptables / nftables），
  含 [全 UDP 端口封禁模式](docs/firewall.md#全-udp-端口封禁模式full_ban)。
- [UPnP 拦截](docs/upnp.md)：`[upnp]` 拦截设备向路由器发起的 UPnP 请求。
- [HTTP API](docs/http.md)：`[http]` 运行时状态读取、手动解封、重载配置（含跨重启继承封禁状态）。

### 隐私模式（`hide_address`）

开启后（配置文件 `hide_address = true`，或命令行 `-H` / `--hide-address`），日志中会**隐藏设备自身的身份信息**：

- **MAC** 与**设备的 IPv6**只保留**前两段与最后一段**，中间以 `...` 省略：
  `60:21:01:1b:0a:23` → `60:21:...:23`，`2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3` → `2408:8240:...:b2a3`。
- **设备的公网 IPv4** 只保留**首段与末段**，中间两段以 `*` 替换：`112.245.115.51` → `112.*.*.51`。
- **内网 IPv4**（如 `192.168.1.100`）不属于公网地址，**保持原样**。
- 只隐藏**设备自己**的地址；**设备外连的远端对端 IP**（告警中的「相关IP」）**不受影响**，始终完整展示。

> 该选项仅影响**日志展示**，不影响黑白名单过滤与防火墙封禁（封禁仍使用真实 MAC / IP）。

### 输出示例

```
2026/10/03 12:00:02 日志时区：CST（来源：/etc/TZ，当前偏移 +08:00）
2026/10/03 12:00:02 已加载配置文件：config.toml
2026/10/03 12:00:02 名单：黑名单（只检测名单内的 2 个设备）
2026/10/03 12:00:02 已启用防火墙对接：nftables（bridge pcdn_detect 集合 banned，按源 MAC + UDP 端口丢弃）
2026/10/03 12:00:02 开始监听网卡 br-lan：触发阈值=20，时长=1m0s，持续提示时长=10m0s，扫描间隔=2s
2026/10/03 12:00:42 00:11:22:33:44:55(192.168.1.100) 的端口 40000 疑似产生PCDN行为（近 1m0s 内 27 个对端IP，累计上行 3.4MiB / 下行 12.1KiB），相关IP为: 1.2.3.4, 5.6.7.8, 9.10.11.12, ...
2026/10/03 12:01:30 00:11:22:33:44:55(192.168.1.100) 的端口 40000 持续产生PCDN行为（本轮累计 31 个对端IP，累计上行 4.1MiB / 下行 15.2KiB），新增相关IP为: 13.14.15.16, 17.18.19.20
2026/10/03 12:09:05 00:11:22:33:44:55(192.168.1.100) 的端口 40000 PCDN行为结束（本轮累计 31 个对端IP，累计上行 5.6MiB / 下行 20.3KiB）
```

## 作为开机自启服务（OpenWrt procd）

新建 `/etc/init.d/pcdn-detect`：

```sh
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    # 配置文件在当前工作目录读取；若想固定使用某目录（如 /etc/pcdn-detect/config.toml），
    # 可改用：procd_set_param command /bin/sh -c 'cd /etc/pcdn-detect && exec /usr/bin/pcdn-detect'
    procd_set_param command /usr/bin/pcdn-detect -i br-lan -n 20 -t 60s
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn
    procd_close_instance
}
```

```bash
chmod +x /etc/init.d/pcdn-detect
/etc/init.d/pcdn-detect enable
/etc/init.d/pcdn-detect start
# 日志可通过 logread 查看
```

## 说明与限制

- 设备归属通过「网卡所在网段」判定：属于本网段/链路本地的为本端设备，其余为远端对端。
  因此请把工具部署在能看到设备真实 MAC 的 **LAN 侧**接口（若网卡无地址会退化为「非公网即本端」的判断）。
- 仅统计全球可路由的远端对端，内网 / 链路本地 / 组播地址会被过滤。
- 日志时间按系统时区显示：依次尝试 `-tz` 参数、`TZ` 环境变量、OpenWrt 的 `/etc/TZ`；
  都不适用时用系统默认（可能是 UTC）。若发现时间与本地不符，可显式指定
  `-tz Asia/Shanghai` 或 `-tz CST-8`。
- 阈值需按实际网络规模调整：过小易误报，过大可能漏报。
