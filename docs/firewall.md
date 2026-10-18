# 防火墙对接（自动封禁 / 解封）

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
| `iptables` | `iptables` 与 `ip6tables` 的**专用链** `PCDN_DETECT`（端口封禁）/ `PCDN_DETECT_UPNP`（UPnP）执行 `-m mac --mac-source <mac> -p <proto> --sport <port> -j DROP`（`<proto>` 为触发协议，`udp` 或 `tcp`）；`chain` / `input_chain` 只是**跳转插入点**（默认 `FORWARD` / `INPUT`） |
| `nftables` | `bridge` 族的指定钩子（端口封禁默认 **`hook = prerouting`**）用**拼接集合**按「源 MAC . 源端口」丢弃；集合按「地址族 + 协议」拆为 `<set>_<family>_<proto>`（如 `banned_v4_udp`），UDP 与 TCP 各自独立；表 / 集合 / 钩子可用 `table`/`set`/`hook` 改，默认 `pcdn_detect`/`banned`/`prerouting`，端口封禁链名固定与表名一致；UPnP 拦截另用独立链（默认 `input_hook = input`） |

后端专用项分别放在同名子表（只解析当前 `backend` 对应的子表；`hook` 的 `{family}` 取 `v4` / `v6`，`{proto}` 为触发协议 `udp` / `tcp`）：

> `iptables` 后端把规则全部写入专用链（`ban_chain` / `upnp_chain`，默认 `PCDN_DETECT` /
> `PCDN_DETECT_UPNP`），并在 `chain` / `input_chain` 指定的链插入一条跳转。因此启动时可以
> **安全地清空并重建专用链**：既清理上一次进程被 SIGKILL / OOM 杀死后残留的封禁，也不会影响
> 用户自己在 `FORWARD` / `INPUT` 中的规则。专用链名可自定义，但**不能与 `chain` /
> `input_chain` 重名**（否则启动清空会误删用户规则），长度不超过 28 且只能包含字母、数字、
> 下划线与连字符。

> `hook` 后端只配**一条命令模板**，由 `{action}` 区分动作（本块为 `ban` / `unban`），
> 使用者自写 sh 包装按 `$1`（action）分发即可。

```toml
[firewall]
enabled = true
backend = "nftables"    # 只解析下面与 backend 同名的子表

[firewall.hook]         # backend = "hook" 时生效
cmd = "my-fw-hook {action} {mac} {ip} {port} {family} {proto}"

[firewall.iptables]     # backend = "iptables" 时生效
chain = "FORWARD"       # 端口封禁的跳转插入点（默认 FORWARD）
input_chain = "INPUT"   # UPnP 拦截的跳转插入点（默认 INPUT）
ban_chain = "PCDN_DETECT"        # 端口封禁专用链名（默认 PCDN_DETECT）
upnp_chain = "PCDN_DETECT_UPNP"  # UPnP 拦截专用链名（默认 PCDN_DETECT_UPNP）

[firewall.nftables]     # backend = "nftables" 时生效
table = "pcdn_detect"
set = "banned"
hook = "prerouting"     # 端口封禁链的钩子（默认 prerouting）
input_hook = "input"    # UPnP 拦截专用链的钩子（默认 input，「进入路由器」方向）
```

## 封禁地址族（`ban_both`）

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

## 进程异常退出与规则残留

正常退出（SIGINT / SIGTERM）会兜底解封并清理规则；启动失败（HTTP 监听 / 抓包初始化失败）也会先
清理再退出。进程被 **SIGKILL / OOM 杀死**时用户态无法自救，依靠以下机制避免规则永久残留：

- `nftables`：启动时**先 `delete table` 再重建**，上次残留的集合元素与规则一并清除，也不会因
  `add` 语义重复累积；
- `iptables`：规则全部在专用链（`ban_chain` / `upnp_chain`）内，启动时清空并重建专用链，
  不影响用户自己的 `FORWARD` / `INPUT` 规则；
- `hook`：由用户命令负责，建议保证 ban / unban 幂等，并在启动时自行清理上次残留。

若希望在进程死后**由内核自动解除**封禁（不必等下次启动），可给 nftables 配置元素超时：

```toml
[firewall.nftables]
ban_ttl = "30m"   # 留空 / 0 = 不设置（默认）
```

启用后端口封禁与全端口封禁的集合元素带 `timeout`，Blocker 会按 `TTL/3` 周期重新 `add` 续期；
进程死亡后元素最迟在 TTL 内自动过期。注意：

- 需要内核 nftables 集合支持 timeout（约 4.8+），且重复 `add` 能刷新超时；
- 若续期失败，封禁可能在告警结束前**提前失效**（fail-open），请先在目标设备上验证；
- 该选项只影响 nftables；`iptables` / `hook` 没有内核级超时语义。

## 全 UDP 端口封禁模式（`[full_ban]`）

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
  - `device`：仅对 **filter 名单中标记 `full_ban = true` 的设备**启用（见 [黑白名单](filter.md)），其余设备不触发。
- **触发条件（`threshold`）**：某设备**被封禁的不同端口数**达到该值（默认 `5`）后触发。
  同一端口的 IPv4 / IPv6 只计为一个端口；UDP / TCP 端口均计入。
- **放行端口（`allow`）**：
  - **留空**（未配置或空数组）时使用**内置常用端口**：**DNS(53)、NTP(123)、DHCP(67/68)、DHCPv6(546/547)**；
  - **显式配置**时以其为准（**不再叠加内置端口**），元素可为整数或端口表达式（如 `"1000-1010"`）；
  - 生成的默认配置文件中已自带该组内置端口，便于按需修改。
- **冗余规则清理**：全端口封禁生效后，会**移除该设备此前已单独下发的冗余 UDP 端口级规则**
  （这些端口已被设备级全封禁覆盖）；TCP 端口不在全 UDP 封禁范围内，其端口级规则保留。
- **触发后新增端口**：设备一旦进入全端口封禁状态，其**全部** UDP 端口已被封禁，此后新触发的端口
  **不再单独下发端口级封禁规则**（避免冗余规则），但仍计入端口统计，使全端口封禁在该设备告警
  全部结束前保持有效；该设备退出 / 端口归零时也无需对应解封这些未单独封禁的端口。
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
