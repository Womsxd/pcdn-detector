# HTTP API

`pcdn-detect` 内置一个可选的 HTTP API，用于读取运行时状态、手动解封、以及重载配置。
默认**关闭**，且默认**仅监听回环地址**（本机访问）。启用后在 `[http]` 配置块中设置。

```toml
[http]
enabled = false                # 是否启用
listen = "127.0.0.1:8080"      # 监听地址；绑定非回环地址时必须设置 token
token = ""                     # Bearer 令牌；非空时要求 Authorization: Bearer <token>
device_ip_limit = 200          # /api/v1/peers 每次最多返回的对端 IP 数
# cors_allowed_origins = []    # 允许的跨域来源；留空不启用 CORS，["*"] 表示任意来源
# cors_allow_credentials = false  # 允许跨域请求携带 Cookie / 凭据；不能与 "*" 组合
# cors_max_age = 600           # 预检结果缓存秒数；0 表示不缓存
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

### 跨域（CORS）

默认**不启用**（不回写任何 `Access-Control-*` 头）。需要浏览器从其它源（如管理页面）直接调用本 API 时，
在 `[http]` 中显式列出允许的来源：

```toml
[http]
cors_allowed_origins = ["https://admin.example.com", "http://192.168.1.10:5173"]
# cors_allow_credentials = false  # 需要跨域携带 Cookie 时设为 true（此时不能用 "*"）
# cors_max_age = 600              # 预检结果缓存 10 分钟；0 表示不缓存
```

- 仅当请求带 `Origin` 且命中允许列表时，才回写 `Access-Control-Allow-Origin`（回显该来源，
  统一附加 `Vary: Origin`）；未命中不回写，由浏览器拦截响应。
- `cors_allowed_origins = ["*"]` 允许任意来源，此时 `Access-Control-Allow-Origin: *`；
  不能同时设 `cors_allow_credentials = true`（配置校验会拒绝）。
- **预检（OPTIONS）在鉴权之前响应**：浏览器不会给预检带 `Authorization`，因此预检不受 token 限制；
  实际请求仍需按上文的 Bearer 规则鉴权（`Authorization` 已默认列入允许的请求头）。
- `Access-Control-Allow-Methods` 取自实际路由表（`GET` 路径同时允许 `HEAD`）；
  预检未知路径返回 404、方法未注册返回 405（带 `Allow` 头），语义与普通请求一致。
- `Access-Control-Allow-Headers` 回显浏览器请求的头名（缺失时回退 `Authorization, Content-Type`）。
- 来源配置支持 `http` / `https`，可带端口；不接受路径、查询串。改动后可热重载生效（见下）。
- 注意：CORS 只约束**浏览器能否读取响应**，并不阻止请求本身。若用 `token = "allow-no-token"`
  关闭了鉴权且监听非回环地址，跨站页面仍可发起写请求（CSRF），请仅在可信网络中使用。

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
- 行为边界（状态码、keep-alive、流水线、连接关闭语义等）有与 `net/http` 的差分测试，
  见 `internal/minihttp/diff_test.go`。

## 端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/health` | 存活探测：`{"status":"ok","uptime_seconds":N}` |
| GET | `/api/v1/status` | 汇总：跟踪设备数、累计告警数、当前封禁条目数、全端口封禁设备数、UPnP 状态 |
| GET | `/api/v1/devices` | 设备级汇总：每设备 IPv4 / IPv6 当前跟踪的端口条目数与封禁条目数（**不含端口明细**） |
| GET | `/api/v1/device` | 单设备端口明细，可按地址族（v4 / v6）与封禁状态筛选（见下） |
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
curl -s 'localhost:8080/api/v1/device?mac=aa:bb:cc:dd:ee:ff&family=v4&state=banned'
curl -s 'localhost:8080/api/v1/peers?mac=aa:bb:cc:dd:ee:ff&port=40000&proto=udp'
curl -s localhost:8080/api/v1/blocks
curl -s localhost:8080/api/v1/dev/memory
curl -s -XPOST localhost:8080/api/v1/unban \
  -d '{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}'

# 配置 token 后
curl -s -H 'Authorization: Bearer <token>' localhost:8080/api/v1/status
```

### `/api/v1/devices`、`/api/v1/device` 与 `/api/v1/peers`

`/api/v1/devices` 只返回设备级汇总：每设备 IPv4 / IPv6 当前跟踪的端口条目数与其中处于封禁
状态的条目数，并再按 `udp` / `tcp` 拆分，**不返回端口明细**。端口条目数按地址族分别统计，
总和与 `[memory] max_ports` 的口径一致。

响应顶层另含两个累计计数：`port_evictions`（因 `[memory] max_ports` 达到上限而提前过期的端口数）
与 `port_drops`（因上限且无端口可淘汰而丢弃的新端口报文数）；两者均为 0 表示上限尚未生效。

```json
{
  "tracked_devices": 1,
  "alerts": 2,
  "port_evictions": 0,
  "port_drops": 0,
  "devices": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "ipv4": {
        "ports": 12, "banned": 3,
        "udp": {"ports": 10, "banned": 3},
        "tcp": {"ports": 2, "banned": 0}
      },
      "ipv6": {
        "ports": 2, "banned": 0,
        "udp": {"ports": 2, "banned": 0},
        "tcp": {"ports": 0, "banned": 0}
      }
    }
  ]
}
```

需要查看某设备的端口明细时，调用 `/api/v1/device`（`mac` 必填）：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `mac` | 是 | 设备 MAC |
| `family` | 否 | `all`（默认）/ `v4` / `v6`；兼容 `ipv4` / `ipv6` |
| `state` | 否 | `all`（默认）/ `banned` / `unbanned`（按当前封禁状态筛选） |
| `limit` | 否 | 每页的端口条目上限；默认 200，最多 1000 |
| `page` | 否 | 页码，从 1 开始；默认 1 |

```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "full_banned": false,
  "ipv4": {
    "ports": 12, "banned": 3,
    "udp": {"ports": 10, "banned": 3},
    "tcp": {"ports": 2, "banned": 0}
  },
  "ipv6": {
    "ports": 2, "banned": 0,
    "udp": {"ports": 2, "banned": 0},
    "tcp": {"ports": 0, "banned": 0}
  },
  "page": 1,
  "limit": 200,
  "matched": 3,
  "truncated": false,
  "ports": [
    {"port":40000,"proto":"udp","v6":false,"peer_count":5,"up_bytes":1024,"down_bytes":2048,"alerting":true,"banned":true}
  ]
}
```

- `ipv4` / `ipv6` 的统计始终为该设备的全量口径，不受 `family` / `state` / `limit` / `page` 影响；
  其中 `ports` / `banned` 为该地址族合计，`udp` / `tcp` 为按传输层协议的拆分。
- `matched` 为符合筛选条件的端口条目总数（不受分页影响）；`truncated` 表示本页之后是否还有条目。
- `page` 为 1-based 页码，偏移按生效的 `limit` 计算（`offset = (page-1) × limit`）；`limit` 为实际生效值。
- `banned` 按当前已生效的封禁状态判定：设备级全 UDP 端口封禁（`[full_ban]`）生效时，该设备
  除 `allow` 放行端口外的所有 UDP 端口均视为封禁（`full_banned = true`）；端口级规则命中时
  即使端口在放行名单内也视为封禁。`ban_both = true` 时端口级规则同时覆盖 IPv4 与 IPv6，
  否则按触发地址族分别判定。
- 明细按「端口 → 协议 → 地址族」排序，IPv4 在前。
- 未跟踪的设备返回 404；参数非法返回 400。

需要查看某个端口的对端 IP 时，按需调用 `/api/v1/peers`：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `mac` | 是 | 设备 MAC |
| `port` | 是 | 本地端口（0-65535） |
| `proto` | 否 | `udp`（默认）/ `tcp` |
| `v6` | 否 | `true` / `false`（默认），地址族 |
| `limit` | 否 | 每页的 IP 上限；默认 `device_ip_limit`，且不能超过该值 |
| `page` | 否 | 页码，从 1 开始；默认 1 |

```json
{"port":40000,"proto":"udp","v6":false,"page":1,"limit":200,"peer_count":5,"peer_ips":["1.1.1.1","1.1.1.2"],"truncated":false}
```

- `peer_count` 为该端口真实对端数，不受分页影响。
- 对端 IP 按地址数值序排序（IPv4 / IPv6 各自按地址大小）；只构造当前页的 IP，`truncated` 表示本页之后是否还有对端。
- `limit` 为实际生效值（默认 `device_ip_limit`，且请求值不能超过它），偏移按 `(page-1) × limit` 计算。
- `device_ip_limit`（默认 200）约束单页返回的 IP 数，避免单次响应构造过大内存。
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
（**不重启进程**）。重载在改动任何运行状态之前会先做完整的配置校验（与 `-T` / `--test-config` 相同），
**校验失败则拒绝本次重载**（HTTP 返回 400；SIGHUP 仅记录日志），当前配置与运行状态保持不变。

成功时返回：

```json
{"applied":["capture","firewall","detect"],"restart_required":null,"restarting":false}
```

### 全部原地生效

| 变更 | 生效方式 |
| --- | --- |
| `[memory] memory_limit` / `gc_percent` | `debug.SetMemoryLimit` / `SetGCPercent` |
| `[detect]` 阈值 / 时长 / 持续期 / 扫描间隔 | detector 原地更新（扫描间隔自下一 tick 起生效） |
| `[memory] low_memory` / `peer_limit` | detector 原地更新 |
| `[log] level` | 日志等级即时生效（`debug` / `info` / `warn` / `error`） |
| `[log] timezone` / `hide_address` | 时区即时切换；隐私模式影响后续日志掩码 |
| `[filter]` 黑白名单 | 过滤器原地替换 |
| `[capture]` 协议 / snaplen / 混杂模式 | 在既有抓包 socket 上重设内核 BPF / 切换混杂模式 |
| `[capture]` 网卡 / 环形缓冲 | **原地重开抓包 socket**（afpacket 不支持在既有 socket 上修改这两项，重开期间可能有极短丢包） |
| `[firewall]` / `[full_ban]` / `[upnp]` | **原地迁移**防火墙与 blocker：旧后端解封并清理后，新后端按内存快照重新下发；Blocker 对象不变（sink / HTTP 指针不换绑），迁移期间的事件排队处理、不会丢失 |
| `[http] token` / `device_ip_limit` | HTTP 服务原地更新（`device_ip_limit` 自下一次 `/peers` 请求起生效） |
| `[http] cors_*` | CORS 策略原地更新，自下一次请求起生效 |
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
