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
5. 若配置了**黑白名单**，则按设备 MAC（黑/白名单均可再限定端口）过滤需要检测的设备，详见「黑白名单」。
6. 若启用了**防火墙对接**，首次告警时自动封禁该设备在该端口上的流量（封禁协议随 `[capture] protocol` 变化：`udp` 仅 UDP、`tcp` 仅 TCP、`all` 为 UDP+TCP），「PCDN行为结束」时自动解封，详见「防火墙对接」。
7. 若启用了**全 UDP 端口封禁模式**（独立的 `[full_ban]` 配置块），某设备**被封禁的不同端口数**达到阈值后，会进一步对该设备**封禁全部 UDP 端口**（仅放行 DNS / NTP / DHCP 等常用端口及自定义放行端口），被封禁端口全部解除后自动解除，详见「全 UDP 端口封禁模式」。
8. 若启用了 **UPnP 拦截**（独立的 `[upnp]` 配置块），会拦截**设备向路由器发起的 UPnP 请求**（SSDP 发现 + HTTP 控制）：**黑名单模式**下仅拦截名单内设备；**白名单模式**下拦截全部、仅放行名单内设备；程序退出时自动解除，详见「UPnP 拦截」。

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
```

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

生成的配置文件示例（可直接编辑）：

配置按功能分块（`[detect]` / `[capture]` / `[memory]` / `[log]` / `[filter]` / `[firewall]` / `[full_ban]` / `[upnp]`）。
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

### 内存占用（低内存设备）

本工具针对低内存路由器做了专门优化。内存主要由三部分构成：**内核抓包环形缓冲**、
**Go 运行时**、**用户态检测数据结构**。

- **内核抓包缓冲**：AF_PACKET 环形缓冲总内存 ≈ `block_size * num_blocks`，默认 **2MiB**
  （`262144 * 8`），远低于常见抓包默认的十几 MiB。若高吞吐下出现丢包，可增大 `num_blocks`
  （如 `64` = 16MiB）；内存特别紧张时可减半（如 `num_blocks = 4`）。
  - `frame_size`：单个帧上限（字节），须 ≥ 最大报文长度，且能整除 `block_size`；
  - `block_size`：每个块大小（字节），须为页大小(4096)与 `frame_size` 的整数倍；
  - `num_blocks`：块数量（≥ 1）。
  - 上述参数非法时自动回退到内置默认值；启动日志会输出实际生效的缓冲大小。
- **内核层 BPF 过滤（收益最大）**：启动时给抓包 socket 附加经典 BPF 过滤器，只放行
  **可能承载所选传输层协议的 IPv4/IPv6 报文**（兼容 VLAN / QinQ）。ARP、STP、IPv4 ICMP/IGMP、
  IPv6 ICMPv6/NDP 等无关报文在**内核环形缓冲之前**即被丢弃，不再复制到用户态被 `handle`
  解析后丢弃，显著降低 CPU 与内存带宽占用。
  - 由 `[capture] protocol` 控制（**默认 `"udp"`**）：`"udp"` 仅放行 UDP、`"tcp"` 仅放行 TCP、
    `"all"` 同时放行 UDP 与 TCP。`"all"` 时该过滤器是解析逻辑的**严格子集**，被丢弃的报文
    原本也会被丢弃，不改变检测语义（IPv4 分片、IPv6 扩展头等场景均不受影响）；`"udp"` / `"tcp"`
    时另一种协议不再参与统计。
- **对端统计**：远端地址以「地址族对应的紧凑值」作为 map 键——IPv4 用 `netip.Addr.As4()` 的
  **4 字节**（`peerKey4`），IPv6 用 `As16()` 的 **16 字节**（`peerKey6`），而非 24 字节的
  `netip.Addr`（其 8 字节的“地址种类”指针在同一个 map 内是冗余的）。由于按键的地址族已分表，
  纯 IPv4 场景下每个键仅 4 字节，比统一用 `As16()`（16 字节）省 12 字节；同时不再为每个对端保留
  IP 字符串与端口集合，IP 仅在输出告警时按需格式化。
- **告警期标记**：告警期间「已提示对端」的标记直接复用对端记录（`peer.reported`），并只额外
  维护一个计数，不再单独维护一份与对端集合同规模的 `reported` 集合。该改动约省下 **40%** 的
  对端内存，并避免长时间告警（持续续期）时该集合只增不减导致内存持续增长。
- 对端时间戳以 `int64`（Unix 纳秒）保存，每个对端再省 16 字节。
- **端口告警续期时间同样以 `int64`（Unix 纳秒）保存**（`portStat.alertStartNano`），而非 24 字节的
  `time.Time`，每个端口再省 16 字节。
- **对端级不再保存字节数**：每个对端的上行 / 下行字节数从未被读取（流量只按端口级
  `portStat.upBytes` / `downBytes` 累计），属于纯冗余字段。去掉后 `peer` 由 32 字节缩到
  16 字节，`map[peerKey4]peer` 的 value 数组随之减半，每记录一个对端省下约 35 字节（约 44%）。
- **端口设备 IP 紧凑化**：`portStat.ip` 由 24 字节的 `netip.Addr` 改为 16 字节的 `[16]byte`
  （`ipRaw`），地址族由端口键 `portKey.v6` 提供——`netip.Addr` 内 8 字节的“地址种类”哨兵指针在此处
  完全冗余（与对端 map 键的处理同理）。`portStat` 由 **96 字节缩到 88 字节**，每个端口省 8 字节
  （32 位平台省 4 字节）；IP 仅在告警时按需格式化。
- **端口 / 设备状态不再重复保存键字段**：`portStat` 的 `port` / `proto` / `v6` 与 `ports` 的键
  `portKey` 逐字段重复，`device.mac` 与 `devices` 的键重复，均删除，改由调用方（`Observe` /
  `Scan` 遍历）把键传入。含结构体填充后，`portStat` 由 **88 字节缩到 80 字节**——恰好从 Go 的
  96 字节分配档降到 80 字节档，每个端口实际省 **16 字节**堆内存；`device` 由 24 字节缩到 16 字节，
  每个设备省 8 字节。
- 抓包层直接由报文原始字节构造地址，**每个报文不再分配 IP 字符串**，降低 GC 压力。
- **map 收缩（回收空闲 bucket）**：Go 的 map 删除元素后**不会收缩底层 bucket 数组**，长期
  运行时曾达到峰值的 map（设备 / 端口 / 对端三级）会一直驻留内存，是“内存不回落”的主因。
  每次扫描时记录各级 map 的元素数峰值，当当前元素数降到峰值 **1/4 以下**（且峰值 ≥ 64）时
  重建该 map，把多余 bucket 归还运行时。该机制仅对“峰值大、当前小”的 map 触发，避免抖动。
- **Go 堆内存软上限**：配置 `[memory] memory_limit`（如 `"24MiB"`；也可用 Go 运行时原生识别的环境变量
  `GOMEMLIMIT`）后，达到该上限时 GC 会更积极地回收，避免长期运行时内存膨胀被系统 OOM。
  建议设为设备可用内存的一半左右，例如 128MB 内存的路由器可设 `"32MiB"`。
  - 注意：`GOMEMLIMIT` 只统计 **Go 堆**，不含 mmap 进进程的**抓包环形缓冲**（默认 2MiB，其驻留页计入 RSS）。
    因此设置时应预留环形缓冲大小 + 2~3MiB 余量。
- **GC 目标百分比（`[memory] gc_percent`，对应 `debug.SetGCPercent`）**：GOGC 语义，堆内新增数据达到
  「存活堆 × `gc_percent`/100」时触发 GC。未配置时用运行时默认（`GOGC=100`，即堆翻倍才触发），也尊重
  环境变量 `GOGC`。低内存设备可设 **20~50**：常驻堆峰值更低，代价是 GC 更频繁、CPU 占用略升。
  - 取值范围 `1~1000`，推荐 `20~50`；`-1` 会**关闭 GC**，不支持。
  - 与 `memory_limit` **不冲突**：堆逼近软上限时由软上限追加收紧，远离上限时由本项决定，两者叠加各管一段。
- **低内存模式（`[memory] low_memory`，或命令行 `-L` / `--low-memory`）**：内存极度受限、且只关心
  「是否触发 PCDN」而不关心具体对端时启用。某「设备 + 端口」一旦达到阈值触发告警，即
  **清空已记录的对端 IP 列表**（对端 map 置 nil，释放其 bucket 交还运行时）并**不再记录该
  端口的新对端 IP**，只保留触发状态（告警续期、累计流量、累计对端计数）继续统计：期间仍有
  流量则续期，超过 `alert_duration` 无流量则输出「PCDN行为结束」；结束后恢复正常统计，可
  再次触发。
  - 代价：该端口告警期间不再输出「持续产生PCDN行为（新增相关IP）」，也不展示持续新增的对端
    IP；首次告警日志仍会输出触发时窗口内的**完整对端 IP 列表**。
  - 效果：触发后该端口的对端统计不再随对端数量增长，避免长期告警（滑动续期）时内存持续攀升。
  - 另外：未显式配置 `peer_limit` 时，其默认值会由 `max(1000, threshold × 10)` **收敛为
    `threshold`**（见下条），进一步压低**触发前**的对端内存。
- **单端口对端记录上限（`[memory] peer_limit`，或命令行 `--peer-limit`）**：为每个「设备 + 端口」的
  对端统计设置上限，防止单个端口（如异常放大的 PCDN 端口）在窗口内记录无限多的对端而占用
  大量内存。达到上限后**不再记录该端口的新对端 IP**（已有对端仍照常刷新与累计，端口级流量
  仍完整累计）。
  - 取值：省略该项时默认取 `max(1000, threshold × 10)`；**开启低内存模式（`low_memory = true`）时
    默认改为 `threshold`**（该模式达阈值即触发并清空对端，无需保留更多）；`0` 表示**不限制**；
    大于 `0` 但小于 `threshold` 时**自动提升为 `threshold`**，以保证仍能达到触发阈值。
    显式配置的 `peer_limit` 始终优先于上述默认值（低内存模式下也不例外）。
  - 代价：达到上限后该端口不再输出其新增的对端 IP（「相关IP」与「持续产生PCDN行为」中的
    新增 IP 均受此上限约束）。
  - 说明：与低内存模式相互独立，可同时启用；低内存模式在告警后清空对端，本上限在告警前
    （及告警结束恢复统计后）约束对端增长。

> 抓包协议也可用命令行 `-P` / `--protocol` 指定（`udp` / `tcp` / `all`），优先级高于配置文件。
> 缓冲（`frame_size` / `block_size` / `num_blocks`）、`memory_limit` 与 `gc_percent` 暂无对应命令行参数，请通过配置文件调整。

> 量化参考（单设备单端口 2 万个 **IPv4** 对端、处于告警态）：去除对端级冗余字节字段后每个
> 对端约占 **44 字节**（此前约 79 字节，再下降约 **44%**；相对最初约 184 字节则下降约 **76%**）。
> 可执行 `go test ./internal/detector/ -run '^$' -bench RetainedBytesPerPeer -benchtime 3x` 复现。
>
> map 收缩参考：单端口 2 万个对端缩到 1 个后触发重建，可回收约 **0.85 MiB**。可执行
> `go test ./internal/detector/ -run '^$' -bench MapShrinkReclaim -benchtime 3x` 复现。

### 黑白名单

按**设备 MAC** 过滤检测范围，配置在 `[filter]` 块内，用 `list_mode` 选择模式（**留空默认白名单**）。
名单为 **TOML 数组表**（`[[filter.blacklist]]` / `[[filter.whitelist]]`），每条需写 `mac`：

```toml
# 黑名单：只检测名单内的设备，其余一律不检测
[filter]
list_mode = "blacklist"

[[filter.blacklist]]
mac = "aa:bb:cc:dd:ee:ff"            # 省略 ports = 该设备全部端口

[[filter.blacklist]]
mac = "11:22:33:44:55:66"
ports = [40000, 40001]               # 指定 ports = 只检测这些端口（范围不足可能漏检）

[[filter.blacklist]]
mac = "60:21:01:1b:0a:23"
full_ban = true                      # [full_ban] mode = "device" 时，为该设备启用全 UDP 端口封禁

[[filter.blacklist]]
mac = "70:31:02:2c:1b:34"
upnp = true                          # [upnp] mode = "device" 时，为该设备启用 UPnP 拦截

# 白名单：名单内命中的设备（或指定端口）不检测，其余照常检测
[filter]
list_mode = "whitelist"

[[filter.whitelist]]
mac = "aa:bb:cc:dd:ee:ff"            # 省略 ports = 全部端口

[[filter.whitelist]]
mac = "11:22:33:44:55:66"
ports = [40000, 40001]               # 指定端口（整数）

[[filter.whitelist]]
mac = "22:33:44:55:66:77"
ports = ["40000-40010", "80/443"]    # 端口表达式（字符串）
```

- 模式取值：只有 `"whitelist"`（可写 `"white"`，**留空即默认此项**）与 `"blacklist"`（可写 `"black"`）。
  **空白名单即不过滤**（检测全部设备），因此无需单独的「不启用」模式。
- 每条可带 **`enabled`**（默认 `true`），设为 `false` 可**临时停用**该条而无需删除。
- 每条可带 **`full_ban`**（默认 `false`）：设为 `true` 表示**为该校验设备启用「全 UDP 端口封禁」**，
  仅在 `[full_ban] mode = "device"` 时生效（见「全 UDP 端口封禁模式」）。未配置 `full_ban` 即不启用。
- 每条可带 **`upnp`**（默认 `false`）：设为 `true` 表示**为该校验设备启用「UPnP 拦截」**，
  仅在 `[upnp] mode = "device"` 时生效（见「UPnP 拦截」）。注意方向：**黑名单模式**下标记的是要**拦截**的设备，
  **白名单模式**下标记的是要**放行**（例外）的设备。
- **黑名单**：命中（MAC 相同）的设备**才会**被检测，其余设备即使达到阈值也不告警；`ports` 省略或为空 =
  该设备**全部端口**，指定 `ports` 则**只检测这些端口**（元素可为整数或端口表达式字符串，同白名单）。
  - ⚠️ 配置了 `ports` 时请确保端口范围覆盖该设备实际使用的端口：**范围不足可能导致漏检（缺少拦截）**。
    启动时会就此输出**告警**提示（`警告：黑名单中 N 个条目配置了端口……`）。
- **白名单**：命中的设备**不检测**；`ports` 省略或为空 = 该设备**全部端口**，元素可为整数或端口表达式字符串，
  表达式支持范围 `a-b` 与斜杠列表 `a/b`（可混用）。
- MAC 大小写不敏感。条目用结构体承载，便于将来按 MAC 扩展更多字段（如独立阈值、时间窗等）。
- ⚠️ `[filter] list_mode = "blacklist"` 但名单为空时会**报错退出**（否则将不检测任何设备）；
  黑名单条目缺少 `mac`、或端口表达式非法也会报错。
- 名单仅在配置文件中设置（暂无对应命令行参数）；启动日志会输出摘要，例如
  `名单：黑名单（只检测名单内的 2 个设备）`、`名单：黑名单（只检测名单内的 2 个设备，其中 1 个仅限指定端口）`、
  `名单：白名单（名单内 2 个 MAC 不检测，其中 1 个仅限指定端口）`。

### 防火墙对接（自动封禁 / 解封）

开启后：某设备某端口首次触发 PCDN 告警即**封禁该设备在该端口上的流量**；
输出「PCDN行为结束」时**解封**；程序退出时对所有仍处于封禁状态的条目**兜底解封**。
**封禁协议随触发报文**：UDP 触发的告警只封禁 UDP，TCP 触发的告警只封禁 TCP
（同一「MAC + 端口」上的 UDP 与 TCP 各自独立封禁 / 解封）。
`[capture] protocol = "udp"`（默认）时抓包层本就只统计 UDP，故只会封禁 UDP；
设为 `"tcp"` 只封 TCP；设为 `"all"` 后同时统计 UDP 与 TCP，两种协议的告警各自封禁对应协议。

```toml
[firewall]
enabled = true
backend = "hook"      # hook / iptables / nftables
# 后端专用项放在与后端同名的子表里（[firewall.hook] / [firewall.iptables] /
# [firewall.nftables]），只解析当前 backend 对应的子表，详见下文。
```

| backend | 说明 |
| --- | --- |
| `hook` | 自定义命令（**单条模板**，`{action}` 区分动作），支持 `{action}` `{mac}` `{ip}` `{port}` `{family}` `{proto}` 占位符，可适配任意防火墙 |
| `iptables` | `iptables` 与 `ip6tables` 的指定链（端口封禁默认 `chain = FORWARD`；「进入路由器」的 UPnP 拦截默认 `input_chain = INPUT`）执行 `-m mac --mac-source <mac> -p <proto> --sport <port> -j DROP`（`<proto>` 为触发协议，`udp` 或 `tcp`） |
| `nftables` | `bridge` 族的指定钩子（端口封禁默认 **`hook = prerouting`**）用**拼接集合**按「源 MAC . 源端口」丢弃；集合按「地址族 + 协议」拆为 `<set>_<family>_<proto>`（如 `banned_v4_udp`），UDP 与 TCP 各自独立；表 / 集合 / 钩子可用 `table`/`set`/`hook` 改，默认 `pcdn_detect`/`banned`/`prerouting`，端口封禁链名固定与表名一致；UPnP 拦截另用独立链（默认 `input_hook = input`） |

后端专用项分别放在同名子表（只解析当前 `backend` 对应的子表；`hook` 的 `{family}` 取 `v4` / `v6`，`{proto}` 为触发协议 `udp` / `tcp`）：

> `hook` 后端只配**一条命令模板**，由 `{action}` 区分动作（本块为 `ban` / `unban`），
> 使用者自写 sh 包装按 `$1`（action）分发即可。

```toml
[firewall]
enabled = true
backend = "nftables"    # 只解析下面与 backend 同名的子表

[firewall.hook]         # backend = "hook" 时生效
cmd = "my-fw-hook {action} {mac} {ip} {port} {family} {proto}"

[firewall.iptables]     # backend = "iptables" 时生效
chain = "FORWARD"       # 端口封禁链名（默认 FORWARD）
input_chain = "INPUT"   # 「进入路由器」的链名（默认 INPUT），用于 UPnP 拦截（设备→路由器流量）

[firewall.nftables]     # backend = "nftables" 时生效
table = "pcdn_detect"
set = "banned"
hook = "prerouting"     # 端口封禁链的钩子（默认 prerouting）
input_hook = "input"    # UPnP 拦截专用链的钩子（默认 input，「进入路由器」方向）
```

#### 封禁地址族（`ban_both`）

用 `ban_both` 一个开关控制是**同时封禁**还是**单独封禁**：

```toml
[firewall]
ban_both = true   # 默认：同时封禁设备的 IPv4 与 IPv6
# ban_both = false # 按触发到的地址族单独封禁（v4 / v6 各自独立封禁 / 解封）
```

- `ban_both = true`（默认）：任一地址族触发，都**同时封禁该设备的 IPv4 与 IPv6**；
  同一「MAC + 端口 + 协议」在两个地址族上重复触发只封一次（引用计数按「MAC + 端口 + 协议」聚合）。
- `ban_both = false`：**按触发到的地址族单独封禁**——v4 与 v6 各自独立封禁 / 解封，
  引用计数按「MAC + 端口 + 协议 + 地址族」分别统计。
  `iptables` 后端此时 v4 走 `iptables`、v6 走 `ip6tables`；`nftables` 后端此时 v4 元素进 `<set>_v4_<proto>`、v6 进 `<set>_v6_<proto>`。
- `hook` 后端在 `ban_both = true` 时对 `v4`、`v6` **各执行一次命令**，用 `{family}` 区分地址族；
  `{proto}` 为该次封禁的触发协议。若命令模板不含对应占位符，同一命令会被重复执行，请确保其幂等，或改用 `iptables` / `nftables` 后端。

- 封禁粒度为**设备 MAC + 本地端口 + 协议**：不同端口、不同协议分别封禁 / 解封。
- 封禁协议随触发报文：**UDP 触发只封 UDP，TCP 触发只封 TCP**；默认 `[capture] protocol = "udp"` 只统计 UDP，故只会封 UDP。
- 命令在后台协程执行，**不阻塞**抓包与检测；单条命令超时可用 `timeout`（默认 `5s`）调整。
- 启动时会检查后端命令是否存在（`iptables` / `nft`），缺失则**报错退出**。
- 说明：nftables 的 `ether saddr` 仅在 `bridge` / `netdev` 族可用，因此 nftables 后端要求 LAN
  侧为网桥接口（如 `br-lan`）。规则挂在 bridge 族的**可配置钩子**上（`hook`，默认 **prerouting**）：
  prerouting 能看到**所有**进入网桥的帧，既覆盖纯二层桥接转发，也覆盖「发给路由器自身 MAC、随后
  被三层路由转发出去」的 PCDN 流量（若挂在 `forward` 钩子上，后者不会被命中，封禁将失效）。
  因此除非确有需要，应保持默认 `hook = "prerouting"`；改为其他钩子时启动会输出告警。
  链名固定与表名一致，不再单独配置。
- 说明：若 LAN↔WAN 为纯路由、LAN 侧并非网桥接口，`bridge` 族规则不适用，请改用 `iptables` 后端
  或自定义 `hook` 命令。

#### 全 UDP 端口封禁模式（`[full_ban]`）

在「按端口封禁」之上叠加的**设备级**全端口封禁：当某设备**被封禁的不同端口数**达到阈值后，
不再只是逐个端口封禁，而是**封禁该设备的全部 UDP 端口**，仅放行常用端口（DNS/NTP/DHCP 等）
与自定义放行端口，从而彻底阻断其 UDP 方向的 PCDN 流量，同时不影响设备基本联网。

该模式是**独立的配置块**（不复用 `[firewall]` 的字段），但依赖 `[firewall]` 启用（复用其后端）：

```toml
[firewall]
enabled = true
backend = "iptables"

[full_ban]
mode = "device"          # off（默认）/ on / device
threshold = 5            # 被封禁的不同端口数达到该值后触发
allow = [53, 123, 67, 68, 546, 547]  # 放行的 UDP 端口；留空则使用内置常用端口
# 仅 hook 后端需要（单条命令模板，{action} 为 ban / unban，对 v4/v6 各执行一次；
# 占位符 {action} {mac} {ip} {family} {ports}，{ip} 仅当地址族与 {family} 一致时填入）：
# [full_ban.hook]
# cmd = ""
```

- **模式（`mode`）**：
  - `off`（默认）：关闭该功能；
  - `on`：对所有被检测设备启用；
  - `device`：仅对 **filter 名单中标记 `full_ban = true` 的设备**启用（见「黑白名单」），其余设备不触发。
- **触发条件（`threshold`）**：某设备**被封禁的不同端口数**达到该值（默认 `5`）后触发。
  同一端口的 IPv4 / IPv6 只计为一个端口；UDP / TCP 端口均计入。
- **放行端口（`allow`）**：
  - **留空**（未配置或空数组）时使用**内置常用端口**：**DNS(53)、NTP(123)、DHCP(67/68)、DHCPv6(546/547)**；
  - **显式配置**时以其为准（**不再叠加内置端口**），元素可为整数或端口表达式（如 `"1000-1010"`）；
  - 生成的默认配置文件中已自带该组内置端口，便于按需修改。
- **解除条件**：该设备被封禁端口数归零（端口告警全部结束）时自动解除；程序退出时对所有仍处于
  全端口封禁状态的设备兜底解除。
- **作用范围**：按**源 MAC** 对设备生效，对 IPv4 与 IPv6 **同时**起作用（与 `ban_both` 无关）。
- **后端支持**：
  - `iptables`：在链中对设备插入「先 DROP 全部 UDP、再对放行端口 ACCEPT」两条规则（v4/v6 各一套）；
  - `nftables`：新增 MAC 集合与放行端口集合，配套 `accept` + `drop` 规则；
  - `hook`：需额外配置 `[full_ban.hook]` 的单条 `cmd`（`{action}` 为 ban / unban，对 v4/v6 各执行一次），
    支持 `{action}` `{mac}` `{ip}` `{family}` `{ports}`（放行端口逗号列表）占位符；`{ip}` 为设备 IP，
    仅当地址族与 `{family}` 一致时填入，否则为空（供 `iptables` / `ip6tables` 等按族分流）。
- ⚠️ 该模式依赖防火墙对接：`[firewall] enabled = false` 时不会生效（启动时会提示警告）。

### UPnP 拦截（`[upnp]`）

拦截**设备向路由器发起的 UPnP 请求**：阻断发往路由器 UPnP 服务的目的端口（默认 **SSDP 发现 UDP 1900** 与
**HTTP 控制 TCP 5000**，可在 `ports` 修改），用于阻止设备借助 UPnP 在路由器上自动开端口（打洞），
常与 PCDN 治理配合使用。

拦截范围**随 `[filter] list_mode` 变化**（与「被检测设备」的范围一致）：

- **黑名单模式**（`list_mode = "blacklist"`）：**仅拦截名单内设备**；
- **白名单模式**（`list_mode = "whitelist"`）：**拦截全部进入路由器的 UPnP，仅放行名单内设备**（名单即例外）；
  名单为空时即拦截全部、无放行设备。

该模式是**独立的配置块**（不复用 `[full_ban]` 的字段），但依赖 `[firewall]` 启用（复用其后端）：

```toml
[firewall]
enabled = true
backend = "iptables"

[upnp]
mode = "off"              # off（默认）/ on / device
# ports = [1900, 5000]    # 拦截的目的端口（UDP + TCP）；留空则用内置 [1900, 5000]
# 仅 hook 后端需要（默认经防火墙原生命令实现）：
# 单条命令模板，{action} 区分动作，对 v4/v6 各执行一次（{family}）：
# ban / unban（黑名单按设备）、block-all / unblock-all（白名单拦截全部）、allow / disallow（白名单放行设备）；
# 占位符 {action} {mac} {ip} {family} {ports}（{ip} 仅当地址族与 {family} 一致时填入；{ports} 如 1900,5000）。
# [upnp.hook]
# cmd = ""
```

- **模式（`mode`）**：
  - `off`（默认）：关闭该功能；
  - `on`：对**名单内全部设备**启用；
  - `device`：仅对**名单中标记 `upnp = true` 的设备**启用（见「黑白名单」）。
  - 两种模式结合名单方向后的实际效果：
    - **黑名单模式**：`on` = 拦截全部黑名单设备，`device` = 只拦截标记的设备（其余不拦截）；
    - **白名单模式**：`on` = 放行全部白名单设备，`device` = 只放行标记的设备（**其余一律拦截**）。
- **拦截端口（`ports`）**：
  - **留空**（未配置或空数组）时使用内置端口 **`[1900, 5000]`**（SSDP 发现 / HTTP 控制）；
  - **显式配置**时以其为准（**不再叠加内置端口**），元素可为整数或端口表达式（如 `"5000-5100"`）；
  - 同时覆盖 **UDP 与 TCP**：SSDP 为 UDP 1900，HTTP 控制为 TCP（如 5000）。
- **链 / 钩子（「进入路由器」方向）**：执行拦截所用的链/钩子，均可配置，默认取「进入路由器」方向——
  - `iptables` 后端：**`[firewall.iptables] input_chain`**，**留空默认 `INPUT`**；与端口封禁所用的 `chain`
    （默认 `FORWARD`）相互独立；
  - `nftables` 后端：**`[firewall.nftables] input_hook`**，**留空默认 `input`**；UPnP 拦截使用**独立的**
    bridge 基础链（与端口封禁链分开），二者可各挂不同钩子。
  - 特殊网络结构（如路由器作三层转发、UPnP 服务不在本机）可改为其他链/钩子（如 `FORWARD` / `prerouting`）。
- **生效时机**：设备集合与拦截规则在**启动时**确定并立即下发；程序退出时**兜底解除**。
- **作用范围**：设备相关规则按**源 MAC** 生效，对 IPv4 与 IPv6 **同时**起作用（与 `ban_both` 无关）；
  白名单模式的全量拦截规则对所有设备生效。
- **后端支持**：
  - `iptables`：在 `input_chain` 指定的链（默认 `INPUT`——UPnP 请求目的地是路由器自身，故非 `FORWARD`）上
    对 UDP / TCP 各按目的端口（`multiport`）插入规则（v4/v6 各一套）。黑名单模式插按源 MAC 的 **DROP**；
    白名单模式先插**无源 MAC 的全量 DROP**，再为放行设备插 **ACCEPT**（因用 `-I` 插表头，ACCEPT 位于 DROP 之上）；
  - `nftables`：在**独立**的 bridge 基础链（`<table>_upnp`，钩子由 `input_hook` 决定，默认 `input`）中，
    黑名单模式用「被拦截设备 MAC 集合」命中即丢；白名单模式先 `ether saddr @<放行集合> … accept`，
    再对其余 `drop`（v4/v6、UDP/TCP 各一套）；
  - `hook`：需配置 `[upnp.hook]` 的**单条 `cmd`**，由 `{action}` 区分动作（`ban`/`unban`、`block-all`/`unblock-all`、
    `allow`/`disallow`），对 v4/v6 各执行一次（`{family}`）；支持 `{action}` `{mac}` `{ip}` `{family}` `{ports}`
    （`{ip}` 仅当地址族与 `{family}` 一致时填入；`{ports}` 为端口逗号列表）占位符；使用者自写 sh 包装按 `$1` 分发。
- ⚠️ 该模式依赖防火墙对接：`[firewall] enabled = false` 时不会生效（启动时会提示警告）。
- 说明：`on`/`device` 的目标取自**当前名单方向**（黑名单模式取黑名单、白名单模式取白名单）。

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
