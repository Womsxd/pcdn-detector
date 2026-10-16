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

`POST /api/v1/reload` 会**重新读取配置文件**（并重新套用启动时的命令行覆盖值），返回：

```json
{"applied":["filter"],"restart_required":["capture"],"restarting":true}
```

### 热应用（无需重启）

以下变更会**立即生效**：

- `[memory] memory_limit`、`[memory] gc_percent`
- `[log] timezone`
- `[filter]` 黑白名单
- `[http] token`、`[http] device_ip_limit`

### 需重启才能生效

以下项在**构造期即固定**，变更后会触发**重启**：

- `[detect]`、`[capture]`（网卡、环形缓冲、协议、混杂模式等）
- `[log] hide_address`、`[memory] low_memory` / `peer_limit`
- `[firewall]`、`[full_ban]`、`[upnp]`（防火墙对象在启动时构建）
- `[http] enabled` / `listen` / `state_dir`

### 重启与「封禁状态继承」

触发重启时：

1. 先把当前**处于告警中的端口会话**（detector）与**封禁状态**（blocker：端口级封禁、全端口封禁、
   UPnP 拦截/放行）写入**状态文件**；
2. 按**旧后端**完成解封 / 清理防火墙规则（因此**切换防火墙后端**时会先完整清理再继承）；
3. 进程用 `exec` **自重启**；
4. 新进程启动时读取状态文件，按**当前后端**重新下发封禁，随后删除状态文件。

状态文件为**临时文件**（二进制格式，权限 0600），默认位于系统临时目录（如 `/tmp`）下的
`pcdn-detect.state`，可用 `[http] state_dir` 改目录。它仅在**由 reload 触发的重启**时写入；
正常停止（SIGINT / SIGTERM）不写、不继承，仍按现有语义解封并清理规则。

失败兜底：进程崩溃未写状态文件则不继承；状态文件损坏（魔数 / 版本 / CRC 校验失败）则记录警告并按无继承启动。

> 注意：`exec` 自重启依赖可执行文件路径（优先 `os.Executable()`，否则 `/proc/self/exe`）。
> 若你的部署希望「退出后由 procd / systemd 拉起」，也可改为直接退出。

## 与隐私模式的关系

`hide_address` 仅影响**日志展示**；HTTP API 默认返回**原始**（不脱敏）的 MAC / IP，
以便本机管理工具使用。请确保接口仅对本机可达。
