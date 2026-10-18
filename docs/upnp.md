# UPnP 拦截（`[upnp]`）

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
  - `device`：仅对**名单中标记 `upnp = true` 的设备**启用（见 [黑白名单](filter.md)）。
  - 两种模式结合名单方向后的实际效果：
    - **黑名单模式**：`on` = 拦截全部黑名单设备，`device` = 只拦截标记的设备（其余不拦截）；
    - **白名单模式**：`on` = 放行全部白名单设备，`device` = 只放行标记的设备（**其余一律拦截**）。
- **拦截端口（`ports`）**：
  - **留空**（未配置或空数组）时使用内置端口 **`[1900, 5000]`**（SSDP 发现 / HTTP 控制）；
  - **显式配置**时以其为准（**不再叠加内置端口**），元素可为整数或端口表达式（如 `"5000-5100"`）；
  - 同时覆盖 **UDP 与 TCP**：SSDP 为 UDP 1900，HTTP 控制为 TCP（如 5000）。
- **链 / 钩子（「进入路由器」方向）**：执行拦截所用的链/钩子，均可配置，默认取「进入路由器」方向——
  - `iptables` 后端：**`[firewall.iptables] input_chain`**，**留空默认 `INPUT`**，它只是**跳转插入点**
    （规则实际写入专用链，链名由 `upnp_chain` 配置，默认 `PCDN_DETECT_UPNP`）；与端口封禁所用的
    `chain`（默认 `FORWARD`，跳转到 `ban_chain`，默认 `PCDN_DETECT`）相互独立；
  - `nftables` 后端：**`[firewall.nftables] input_hook`**，**留空默认 `input`**；UPnP 拦截使用**独立的**
    bridge 基础链（与端口封禁链分开），二者可各挂不同钩子。
  - 特殊网络结构（如路由器作三层转发、UPnP 服务不在本机）可改为其他链/钩子（如 `FORWARD` / `prerouting`）。
- **生效时机**：设备集合与拦截规则在**启动时**确定并立即下发；程序退出时**兜底解除**。
- **作用范围**：设备相关规则按**源 MAC** 生效，对 IPv4 与 IPv6 **同时**起作用（与 `ban_both` 无关）；
  白名单模式的全量拦截规则对所有设备生效。
- **后端支持**：
  - `iptables`：规则写入专用链 `PCDN_DETECT_UPNP`，并在 `input_chain`（默认 `INPUT`——UPnP 请求目的地
    是路由器自身，故非 `FORWARD`）插入跳转；对 UDP / TCP 各按目的端口（`multiport`）插入规则
    （v4/v6 各一套）。黑名单模式插按源 MAC 的 **DROP**；白名单模式先插**无源 MAC 的全量 DROP**，
    再为放行设备插 **ACCEPT**（因用 `-I` 插表头，ACCEPT 位于 DROP 之上）；
  - `nftables`：在**独立**的 bridge 基础链（`<table>_upnp`，钩子由 `input_hook` 决定，默认 `input`）中，
    黑名单模式用「被拦截设备 MAC 集合」命中即丢；白名单模式先 `ether saddr @<放行集合> … accept`，
    再对其余 `drop`（v4/v6、UDP/TCP 各一套）；
  - `hook`：需配置 `[upnp.hook]` 的**单条 `cmd`**，由 `{action}` 区分动作（`ban`/`unban`、`block-all`/`unblock-all`、
    `allow`/`disallow`），对 v4/v6 各执行一次（`{family}`）；支持 `{action}` `{mac}` `{ip}` `{family}` `{ports}`
    （`{ip}` 仅当地址族与 `{family}` 一致时填入；`{ports}` 为端口逗号列表）占位符；使用者自写 sh 包装按 `$1` 分发。
- ⚠️ 该模式依赖防火墙对接：`[firewall] enabled = false` 时不会生效（启动时会提示警告）。
- 说明：`on`/`device` 的目标取自**当前名单方向**（黑名单模式取黑名单、白名单模式取白名单）。
