# HTTP API

`pcdn-detect` 内置一个可选的 HTTP API，用于读取运行时状态、手动解封、以及重载配置。
默认**关闭**，且默认**仅监听回环地址**（本机访问）。启用后在 `[http]` 配置块中设置。

```toml
[http]
enabled = false                # 是否启用
listen = "127.0.0.1:8080"      # 监听地址；绑定非回环地址时必须设置 token
token = ""                     # Bearer 令牌；非空时要求 Authorization: Bearer <token>
device_ip_limit = 200          # /api/v1/peers 每次最多返回的对端 IP 数
# state_dir = ""               # 重启继承用状态文件目录（二进制）；留空为系统临时目录（如 /tmp）
```

- 使用项目内置的极简 HTTP/1.1 服务端（`internal/minihttp`），**无第三方依赖，仅支持明文 HTTP**。
  不依赖标准库 `net/http`，因此不会带入 `crypto/tls` / `crypto/x509`：可执行文件更小。
  需要加密时请在前置反向代理（如 nginx / stunnel）上终结 TLS，本服务不实现 HTTPS。
- **安全默认**：若 `listen` 绑定到**非回环地址**（如 `0.0.0.0:8080`）却未配置 `token`，启动会被**拒绝**，
  避免接口无意暴露。请勿把该接口直接暴露到公网。
- `token` 非空时，所有请求须带 `Authorization: Bearer <token>`。
- **显式关闭鉴权**：`token = "allow-no-token"` 表示**不校验** Authorization（无 token 也可访问），
  并**允许绑定非回环地址**；适合完全可信的内网 / 本机场景。此配置会在启动日志中给出警告。

### 传输层限制

| 项目 | 限制 | 超限行为 |
| --- | --- | --- |
| 请求行 | 4 KiB | 414 |
| 请求头单行 | 4 KiB | 431 |
| 请求头总量 | 16 KiB | 431 |
| 请求体 | 1 MiB，仅支持 `Content-Length` | 413；chunked 等返回 501 |
| 读请求头 | 5s | 断开连接 |
| 空闲 keep-alive | 30s | 断开连接 |
| 响应写 | 10s | 断开连接 |

- 不支持 HTTPS / HTTP-2 / `Transfer-Encoding: chunked` 请求体；协议级错误（400/413/414/431/501）
  同样返回 `{"error":"..."}`，由 `httpapi` 注入统一的错误渲染（`minihttp` 单独使用时默认 `text/plain`）。
- 所有响应带标准 `Date` 头（IMF-fixdate）；不写 `Server` 头。
- **无 HTTP 构建**：`go build -tags nohttp`（或 `make nohttp`）会产出不含本 API 的最小二进制；
  此时若配置 `[http] enabled = true`，启动会直接报错退出并提示改用常规构建。
- 行为边界（状态码、keep-alive、流水线、连接关闭语义等）有与 `net/http` 的差分测试，
  见 `internal/minihttp/diff_test.go`。

## 端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/health` | 存活探测：`{"status":"ok","uptime_seconds":N}` |
| GET | `/api/v1/status` | 汇总：跟踪设备数、累计告警数、当前封禁条目数、全端口封禁设备数、UPnP 状态 |
| GET | `/api/v1/devices` | 每设备 → 每端口的统计（对端数、收发字节、是否告警中），**不含对端 IP 列表** |
| GET | `/api/v1/peers` | 按需读取单个端口的对端 IP 列表（见下） |
| GET | `/api/v1/blocks` | 当前端口级封禁列表 + 全 UDP 端口封禁设备 + UPnP 拦截/放行状态 |
| GET | `/dev/memory` | 运行时内存 / 诊断（注意：挂载在字面量 `/dev/` 前缀下） |
| POST | `/api/v1/unban` | 手动解封：`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}` |
| POST | `/api/v1/reload` | 重载配置（见下） |

错误响应统一为 `{"error":"..."}`，配合 400（参数错误）/ 401（未授权）/ 413（请求体过大）/
414（请求行过长）/ 431（请求头过大）/ 501（不支持的传输编码）/ 503（依赖未启用）。

### 示例

```bash
curl -s localhost:8080/api/v1/health
curl -s localhost:8080/api/v1/status
curl -s localhost:8080/api/v1/devices
curl -s 'localhost:8080/api/v1/peers?mac=aa:bb:cc:dd:ee:ff&port=40000&proto=udp'
curl -s localhost:8080/api/v1/blocks
curl -s localhost:8080/api/v1/dev/memory
curl -s -XPOST localhost:8080/api/v1/unban \
  -d '{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}'

# 配置 token 后
curl -s -H 'Authorization: Bearer <token>' localhost:8080/api/v1/status
```

### `/api/v1/devices` 与 `/api/v1/peers`

`/api/v1/devices` 只返回每设备 → 每端口的统计信息，**不再内联对端 IP 列表**：设备 / 端口较多时，
汇总响应无需构造大量 IP 字符串，显著降低单次请求的 CPU 与内存压力。

响应顶层另含两个累计计数：`port_evictions`（因 `[memory] max_ports` 达到上限而提前过期的端口数）
与 `port_drops`（因上限且无端口可淘汰而丢弃的新端口报文数）；两者均为 0 表示上限尚未生效。

需要查看某个端口的对端 IP 时，按需调用 `/api/v1/peers`：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `mac` | 是 | 设备 MAC |
| `port` | 是 | 本地端口（0-65535） |
| `proto` | 否 | `udp`（默认）/ `tcp` |
| `v6` | 否 | `true` / `false`（默认），地址族 |
| `limit` | 否 | 本次返回的 IP 上限；默认 `device_ip_limit`，且不能超过该值 |

```json
{"port":40000,"proto":"udp","v6":false,"peer_count":5,"peer_ips":["1.1.1.1","1.1.1.2"],"truncated":false}
```

- `peer_count` 为该端口真实对端数，不受 `limit` 影响。
- 对端 IP 按地址数值序排序（IPv4 / IPv6 各自按地址大小）；超过上限时只构造前 `limit` 个并置 `truncated = true`。
- `device_ip_limit`（默认 200）约束单次返回的 IP 数，避免单次响应构造过大内存。
- 未跟踪的设备 / 端口返回 404。

### `/dev/memory`

返回 `runtime.MemStats` 关键字段，以及当前 `GOMEMLIMIT`（`memory_limit`）、`gc_percent`、
goroutine 数、`GOMAXPROCS`、`NumCPU`、Go 版本与运行时长。

`GOMEMLIMIT` 与 `gc_percent` 取自进程内记录的生效值，读取接口本身不会 stop-the-world，也不会改变
`memory_limit` / `gc_percent` 的设置。

## reload（重载配置）

除了 `POST /api/v1/reload`，还可以用 **`SIGHUP`** 触发同一套重载逻辑：

```bash
kill -HUP <pid>
# OpenWrt：/etc/init.d/pcdn-detect reload（procd 默认就是发送 SIGHUP）
```

- HTTP 未启用（默认）时，SIGHUP 是**唯一**的热重载入口；
- SIGHUP 与 HTTP 请求共用同一把锁，串行执行、可安全并发；
- 重载期间重复到达的 SIGHUP 会**合并为一次**，避免连续 reload。

`POST /api/v1/reload` 会**重新读取配置文件**（并重新套用启动时的命令行覆盖值），**原地应用**变更
（**不重启进程**），返回：

```json
{"applied":["capture","firewall","detect"],"restart_required":null,"restarting":false}
```

### 全部原地生效

| 变更 | 生效方式 |
| --- | --- |
| `[memory] memory_limit` / `gc_percent` | `debug.SetMemoryLimit` / `SetGCPercent` |
| `[detect]` 阈值 / 时长 / 持续期 / 扫描间隔 | detector 原地更新（扫描间隔自下一 tick 起生效） |
| `[memory] low_memory` / `peer_limit` | detector 原地更新 |
| `[log] timezone` / `hide_address` | 时区即时切换；隐私模式影响后续日志掩码 |
| `[filter]` 黑白名单 | 过滤器原地替换 |
| `[capture]` 协议 / snaplen / 混杂模式 | 在既有抓包 socket 上重设内核 BPF / 切换混杂模式 |
| `[capture]` 网卡 / 环形缓冲 | **原地重开抓包 socket**（afpacket 不支持在既有 socket 上修改这两项，重开期间可能有极短丢包） |
| `[firewall]` / `[full_ban]` / `[upnp]` | **原地迁移**防火墙与 blocker：旧后端解封并清理后，新后端按内存快照重新下发；Blocker 对象不变（sink / HTTP 指针不换绑），迁移期间的事件排队处理、不会丢失 |
| `[http] token` / `device_ip_limit` | HTTP 服务原地更新（`device_ip_limit` 自下一次 `/peers` 请求起生效） |
| `[http] enabled` / `listen` | **原地重启 HTTP 监听**（仅重启监听，不重启进程） |

> `[capture] protocol` 变化时，若 `[firewall] enabled = true`，防火墙会**一并原地重建**：
> 封禁协议与 nftables 预建集合（`<set>_<family>_<proto>`）都由它决定，不重建会导致新协议
> （如 `udp` → `all` 后的 TCP）的封禁命令因集合不存在而失败。

### 兜底重启

若某组件**原地重建失败**（如新网卡打不开、新防火墙后端构建报错），回退到「保存状态 + 自重启」：
写状态文件（detector 告警会话 + blocker 封禁状态）→ `exec` 自重启 → 启动时按新后端 `Restore` 继承。
此时响应为 `{"restart_required":["capture"],"restarting":true}`。

> 防火墙迁移失败时，旧后端的规则已在迁移过程中解封 / 清理；由于 blocker 的内存状态会原样写入
> 状态文件，重启后仍能按新后端恢复这批封禁，不会永久丢失。

> 注意：若新配置本身非法导致启动期失败，进程会退出（procd / systemd 托管时可能反复重启），需修正配置。

### 封禁状态继承

- **原地重载**：封禁状态在**内存中转移**（无需状态文件）——迁移前先取当前 `BlockState` 快照，
  按旧后端逐条解封并清理旧规则，再由同一个 Blocker 按新后端 `Restore` 重新下发。Blocker 对象
  保持不变，因此检测层 sink 与 HTTP 持有的指针始终有效，迁移期间到达的告警事件只会排队，不会
  丢给已关闭的对象。
  - 切换后端时仍需「先解封旧后端、再下发新后端」，因此存在一个**极短的无规则窗口**（hook 后端
    取决于自定义命令耗时）；同一后端内的配置调整也会经过该窗口。
  - 若配置了 `[firewall] ban_active_alerts = true`，启用防火墙或 reload 时还会把检测层当前
    **已处于告警中**的端口补发为封禁（幂等），适用于启动时防火墙关闭、运行中才启用的场景。
- **兜底重启**：通过**状态文件**（二进制格式，权限 0600，默认位于系统临时目录下的 `pcdn-detect.state`，
  可用 `[http] state_dir` 改目录）传递。状态文件仅在**兜底重启**时写入；正常停止（SIGINT / SIGTERM）
  不写、不继承，仍按现有语义解封并清理规则。文件损坏（魔数 / 版本 / CRC 校验失败）则记录警告并按无继承启动。

> 切换防火墙后端时会**先按旧后端完整解封、再按新后端继承**，不会残留旧规则。

## 与隐私模式的关系

`hide_address` 仅影响**日志展示**；HTTP API 默认返回**原始**（不脱敏）的 MAC / IP，
以便本机管理工具使用。请确保接口仅对本机可达。
