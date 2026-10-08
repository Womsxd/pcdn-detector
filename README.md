# pcdn-detect — P2P CDN 行为检测工具

在 OpenWrt / Linux 路由器上运行，监听指定网卡，对局域网设备的流量进行抓包分析。
当某台设备（MAC）在**指定时长**内、通过**同一个本地端口**连接了**超过阈值数量**的不同
远端公网 IP 时，判定其疑似存在 PCDN 行为并输出告警。

## 工作原理

1. 启动时读取配置文件（见下「配置文件」），命令行参数可覆盖；指定网卡、触发次数（阈值）、检测时长等。
2. 使用 AF_PACKET（Linux 内核环形缓冲）对该网卡抓包——功能等价于 pcap，
   但为**纯 Go 实现、无 CGO / 无 libpcap 依赖**，可交叉编译为静态文件，便于在 OpenWrt 部署。
   抓包 socket 附带内核层 BPF 过滤器，**默认只放行 UDP**（可用 `[capture] protocol` 设为 `udp` / `tcp` / `all`），
   ARP / STP / ICMP / ICMPv6 等无关报文在进入用户态之前即被丢弃。
3. 解析以太网 / IPv4 / IPv6 / TCP / UDP 头部，识别「局域网设备 <-> 公网对端」的流量，
   按 `设备MAC + 本地端口 + 传输层协议` 分别统计在滑动窗口 `时长` 内出现的不同远端公网 IP 数量。
4. 数量达到 `触发次数` 即输出「疑似产生PCDN行为」告警。随后进入**持续期**（默认 10 分钟，
   可配置）：期间**只要该端口仍有流量（任意对端，无论新旧）**就刷新持续期计时器（即滑动续期），
   不再要求窗口内数量达到阈值；若出现**新的对端 IP**（哪怕只有 1 个）则额外输出
   「持续产生PCDN行为」；若持续 `-alert-duration` 时长内都没有**任何流量**，
   则输出「PCDN行为结束」并结束本轮，之后可重新触发。
5. 若配置了**黑白名单**，则按设备 MAC（白名单还可限定端口）过滤需要检测的设备，详见「黑白名单」。
6. 若启用了**防火墙对接**，首次告警时自动封禁该设备在该端口上的流量（封禁协议随 `[capture] protocol` 变化：`udp` 仅 UDP、`tcp` 仅 TCP、`all` 为 UDP+TCP），「PCDN行为结束」时自动解封，详见「防火墙对接」。

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
- 用 `-c <路径>` / `--config <路径>` 可**显式指定**配置文件：此时只读取该文件（不存在则创建、非法则报错），
  不再走上面的候选顺序。
- **命令行参数优先于配置文件**：显式指定的参数会覆盖文件中的同名配置，未指定则使用文件中的值。

生成的配置文件示例（可直接编辑）：

```toml
# 以 # 开头的行为注释
interface = "br-lan"       # 网卡名称（必填）
threshold = 20             # 触发阈值：窗口内同一设备同一端口的不同远端公网 IP 数
window = "60s"             # 检测时长（滑动窗口）
alert_duration = "10m"     # 持续提示时长
promisc = true             # 是否开启混杂模式
interval = "2s"            # 检测扫描间隔
timezone = "Asia/Shanghai" # 日志时区，留空表示自动读取系统时区
hide_address = false       # 隐私模式：隐藏设备自身的 IPv6/公网地址与 MAC
memory_limit = ""          # Go 堆内存软上限（如 "24MiB"），留空表示不限制；低内存设备建议设置

# 抓包环形缓冲：总内存 = block_size * num_blocks（默认 2MiB，适合低内存设备）
[capture]
frame_size = 65536
block_size = 262144
num_blocks = 8
protocol = "udp"              # 内核层过滤器放行协议：udp（默认）/ tcp / all
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
- 抓包层直接由报文原始字节构造地址，**每个报文不再分配 IP 字符串**，降低 GC 压力。
- **map 收缩（回收空闲 bucket）**：Go 的 map 删除元素后**不会收缩底层 bucket 数组**，长期
  运行时曾达到峰值的 map（设备 / 端口 / 对端三级）会一直驻留内存，是“内存不回落”的主因。
  每次扫描时记录各级 map 的元素数峰值，当当前元素数降到峰值 **1/4 以下**（且峰值 ≥ 64）时
  重建该 map，把多余 bucket 归还运行时。该机制仅对“峰值大、当前小”的 map 触发，避免抖动。
- **Go 堆内存软上限**：配置 `memory_limit`（如 `"24MiB"`；也可用 Go 运行时原生识别的环境变量
  `GOMEMLIMIT`）后，达到该上限时 GC 会更积极地回收，避免长期运行时内存膨胀被系统 OOM。
  建议设为设备可用内存的一半左右，例如 128MB 内存的路由器可设 `"32MiB"`。

> CLI 暂无对应的缓冲 / 内存 / 过滤参数，请通过配置文件 `[capture]`（含 `protocol`）与 `memory_limit` 调整。

> 量化参考（单设备单端口 2 万个 **IPv4** 对端、处于告警态）：键改为 4 字节紧凑值后每个对端
> 约占 **79 字节**，此前约 92 字节，再下降约 **14%**（相对最初约 184 字节则下降约 **57%**）。
> 可执行 `go test -run '^$' -bench RetainedBytesPerPeer -benchtime 3x` 复现。
>
> map 收缩参考：单端口 2 万个对端缩到 1 个后触发重建，可回收约 **1.5 MiB**。可执行
> `go test -run '^$' -bench MapShrinkReclaim -benchtime 3x` 复现。

### 黑白名单

按**设备 MAC** 过滤检测范围，用配置文件的 `list_mode` 选择模式（留空表示不启用）。
名单为 **TOML 数组表**（`[[blacklist]]` / `[[whitelist]]`），每条需写 `mac`：

```toml
# 黑名单：只检测名单内的设备，其余一律不检测（不支持 ports）
list_mode = "blacklist"

[[blacklist]]
mac = "aa:bb:cc:dd:ee:ff"

[[blacklist]]
mac = "11:22:33:44:55:66"

# 白名单：名单内命中的设备（或指定端口）不检测，其余照常检测
list_mode = "whitelist"

[[whitelist]]
mac = "aa:bb:cc:dd:ee:ff"            # 省略 ports = 全部端口

[[whitelist]]
mac = "11:22:33:44:55:66"
ports = [40000, 40001]               # 指定端口（整数）

[[whitelist]]
mac = "22:33:44:55:66:77"
ports = ["40000-40010", "80/443"]    # 端口表达式（字符串）
```

- 模式取值：`"blacklist"`（可写 `"black"`）、`"whitelist"`（可写 `"white"`）；留空 / `"none"` / `"off"` 表示不启用。
- 每条可带 **`enabled`**（默认 `true`），设为 `false` 可**临时停用**该条而无需删除。
- **黑名单**：命中（MAC 相同）的设备**才会**被检测，其余设备即使达到阈值也不告警；条目**不支持 `ports`**。
- **白名单**：命中的设备**不检测**；`ports` 省略或为空 = 该设备**全部端口**，元素可为整数或端口表达式字符串，
  表达式支持范围 `a-b` 与斜杠列表 `a/b`（可混用）。
- MAC 大小写不敏感。条目用结构体承载，便于将来按 MAC 扩展更多字段（如独立阈值、时间窗等）。
- ⚠️ `list_mode = "blacklist"` 但名单为空时会**报错退出**（否则将不检测任何设备）；
  黑名单条目带 `ports`、或条目缺少 `mac` 也会报错。
- 名单仅在配置文件中设置（暂无对应命令行参数）；启动日志会输出摘要，例如
  `名单：黑名单（只检测名单内的 2 个设备）`、`名单：白名单（名单内 2 个 MAC 不检测，其中 1 个仅限指定端口）`。

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
```

| backend | 说明 |
| --- | --- |
| `hook` | 自定义命令，支持 `{mac}` `{ip}` `{port}` `{family}` `{proto}` 占位符，可适配任意防火墙 |
| `iptables` | `iptables` 与 `ip6tables` 的 FORWARD 链执行 `-m mac --mac-source <mac> -p <proto> --sport <port> -j DROP`（链名可用 `chain` 改；`<proto>` 为触发协议，`udp` 或 `tcp`） |
| `nftables` | `bridge` 族，用**拼接集合**按「源 MAC . 源端口」丢弃；集合按「地址族 + 协议」拆为 `<set>_<family>_<proto>`（如 `banned_v4_udp`），UDP 与 TCP 各自独立；表 / 集合 / 链可用 `table`/`set`/`chain` 改，默认 `pcdn_detect`/`banned`/`forward` |

`hook` 示例（`{family}` 取 `v4` / `v6`，`{proto}` 为触发协议 `udp` / `tcp`）：

```toml
[firewall]
enabled = true
backend = "hook"
ban_cmd = "nft add element bridge filter banned_{family}_{proto} { {mac} . {port} }"
unban_cmd = "nft delete element bridge filter banned_{family}_{proto} { {mac} . {port} }"
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
- 说明：nftables 的 `ether saddr` 仅在 `bridge` / `netdev` 族可用；若你的 LAN↔WAN 为三层路由、
  bridge 族规则不生效，请改用 `iptables` 后端或自定义 `hook` 命令。

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
