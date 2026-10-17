# HTTP API

`pcdn-detect` 内置一个可选的 HTTP API，用于读取运行时状态、手动解封、以及重载配置。
默认**关闭**，且默认**仅监听回环地址**（本机访问）。启用后在 `[http]` 配置块中设置。

```toml
[http]
enabled = false                # 是否启用
listen = "127.0.0.1:8080"      # 监听地址；绑定非回环地址时必须设置 token
token = ""                     # Bearer 令牌；非空时要求 Authorization: Bearer <token>
device_ip_limit = 200          # /api/v1/devices 每个端口最多返回的对端 IP 数
# state_dir = ""               # 重启继承用状态文件目录（二进制）；留空为系统临时目录（如 /tmp）
```

- 使用标准库 `net/http`，无第三方依赖。
- **安全默认**：若 `listen` 绑定到**非回环地址**（如 `0.0.0.0:8080`）却未配置 `token`，启动会被**拒绝**，
  避免接口无意暴露。请勿把该接口直接暴露到公网。
- `token` 非空时，所有请求须带 `Authorization: Bearer <token>`。
- **显式关闭鉴权**：`token = "allow-no-token"` 表示**不校验** Authorization（无 token 也可访问），
  并**允许绑定非回环地址**；适合完全可信的内网 / 本机场景。此配置会在启动日志中给出警告。

## 端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/health` | 存活探测：`{"status":"ok","uptime_seconds":N}` |
| GET | `/api/v1/status` | 汇总：跟踪设备数、累计告警数、当前封禁条目数、全端口封禁设备数、UPnP 状态 |
| GET | `/api/v1/devices` | 每设备 → 每端口的对端统计（对端数、收发字节、是否告警中、对端 IP 列表） |
| GET | `/api/v1/blocks` | 当前端口级封禁列表 + 全 UDP 端口封禁设备 + UPnP 拦截/放行状态 |
| GET | `/dev/memory` | 运行时内存 / 诊断（注意：挂载在字面量 `/dev/` 前缀下） |
| POST | `/api/v1/unban` | 手动解封：`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}` |
| POST | `/api/v1/reload` | 重载配置（见下） |

错误响应统一为 `{"error":"..."}`，配合 400（参数错误）/ 401（未授权）/ 503（依赖未启用）。

### 示例

```bash
curl -s localhost:8080/api/v1/health
curl -s localhost:8080/api/v1/status
curl -s localhost:8080/api/v1/devices
curl -s localhost:8080/api/v1/blocks
curl -s localhost:8080/api/v1/dev/memory
curl -s -XPOST localhost:8080/api/v1/unban \
  -d '{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}'

# 配置 token 后
curl -s -H 'Authorization: Bearer <token>' localhost:8080/api/v1/status
```

### `/api/v1/devices` 与对端 IP 上限

每个端口的对端 IP 列表默认最多返回 `device_ip_limit`（默认 200）个，超出时截断并置
`truncated = true`（`peer_count` 仍为该端口真实对端数）。该上限用于避免单次响应构造过大内存。

### `/dev/memory`

返回 `runtime.MemStats` 关键字段，以及当前 `GOMEMLIMIT`（`memory_limit`）、`gc_percent`、
goroutine 数、`GOMAXPROCS`、`NumCPU`、Go 版本与运行时长。

## reload（重载配置）

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
| `[capture]` 协议 / 混杂模式 | 在既有抓包 socket 上重设内核 BPF / 切换混杂模式 |
| `[capture]` 网卡 / 环形缓冲 | **原地重开抓包 socket**（afpacket 不支持在既有 socket 上修改这两项，重开期间可能有极短丢包） |
| `[firewall]` / `[full_ban]` / `[upnp]` | **原地重建**防火墙与 blocker：先按旧后端解封，再按新后端继承当前封禁 |
| `[http] token` / `device_ip_limit` | HTTP 服务原地更新 |
| `[http] enabled` / `listen` | **原地重启 HTTP 监听**（仅重启监听，不重启进程） |

### 兜底重启

若某组件**原地重建失败**（如新网卡打不开、新防火墙后端构建报错），回退到「保存状态 + 自重启」：
写状态文件（detector 告警会话 + blocker 封禁状态）→ 按旧后端清理 → `exec` 自重启 → 启动时按新后端
`Restore` 继承。此时响应为 `{"restart_required":["capture"],"restarting":true}`。

> 注意：若新配置本身非法导致启动期失败，进程会退出（procd / systemd 托管时可能反复重启），需修正配置。

### 封禁状态继承

- **原地重载**：封禁状态在**内存中转移**（无需状态文件）——重建 blocker 前先取当前 `BlockState`，
  关闭旧 blocker（按旧后端解封）后由新 blocker `Restore` 按新后端重新下发。
- **兜底重启**：通过**状态文件**（二进制格式，权限 0600，默认位于系统临时目录下的 `pcdn-detect.state`，
  可用 `[http] state_dir` 改目录）传递。状态文件仅在**兜底重启**时写入；正常停止（SIGINT / SIGTERM）
  不写、不继承，仍按现有语义解封并清理规则。文件损坏（魔数 / 版本 / CRC 校验失败）则记录警告并按无继承启动。

> 切换防火墙后端时会**先按旧后端完整解封、再按新后端继承**，不会残留旧规则。

## 与隐私模式的关系

`hide_address` 仅影响**日志展示**；HTTP API 默认返回**原始**（不脱敏）的 MAC / IP，
以便本机管理工具使用。请确保接口仅对本机可达。
