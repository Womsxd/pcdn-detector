# pcdn-detect — P2P CDN 行为检测工具

在 OpenWrt / Linux 路由器上运行，监听指定网卡，对局域网设备的流量进行抓包分析。
当某台设备（MAC）在**指定时长**内、通过**同一个本地端口**连接了**超过阈值数量**的不同
远端公网 IP 时，判定其疑似存在 PCDN 行为并输出告警。

## 工作原理

1. 启动时指定网卡、触发次数（阈值）、检测时长。
2. 使用 AF_PACKET（Linux 内核环形缓冲）对该网卡抓包——功能等价于 pcap，
   但为**纯 Go 实现、无 CGO / 无 libpcap 依赖**，可交叉编译为静态文件，便于在 OpenWrt 部署。
3. 解析以太网 / IPv4 / IPv6 / TCP / UDP 头部，识别「局域网设备 <-> 公网对端」的流量，
   统计每个 `设备MAC + 本地端口` 在滑动窗口 `时长` 内出现的不同远端公网 IP 数量。
4. 数量达到 `触发次数` 即输出「疑似产生PCDN行为」告警。此后在**持续提示时长**（默认 10 分钟，
   可配置）内，只要出现**新的对端 IP** 就继续输出「持续产生PCDN行为」，超过时长后静默，
   直到行为停止（对端数低于阈值）后重新触发。

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
/usr/bin/pcdn-detect -i br-lan -c 20 -t 60s
```

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-i` | 空（必填） | 监听的网卡名称，如 `br-lan`、`br0`、`eth0` |
| `-c` | `20` | 触发次数：时长内同一设备同一端口的**不同远端公网 IP** 数量阈值 |
| `-t` | `60s` | 检测时长（滑动窗口），支持 `30s`、`5m`、`1h` 等 |
| `-alert-duration` | `10m` | 首次告警后持续提示的最长时间，超过后静默；支持 `5m`、`30m` 等 |
| `-promisc` | `true` | 是否开启混杂模式 |
| `-interval` | `2s` | 检测扫描间隔 |
| `-tz` | 空 | 日志时区，支持 IANA 名称（`Asia/Shanghai`）或 POSIX 串（`CST-8`）；默认自动读取 |

### 输出示例

```
2026/10/03 12:00:02 日志时区：CST（来源：/etc/TZ，当前偏移 +08:00）
2026/10/03 12:00:02 开始监听网卡 br-lan：触发阈值=20，时长=1m0s，持续提示时长=10m0s，扫描间隔=2s
2026/10/03 12:00:42 00:11:22:33:44:55(192.168.1.100) 的端口 40000 疑似产生PCDN行为（窗口内 27 个对端IP，上行 3.4MiB / 下行 12.1KiB），相关IP为: 1.2.3.4, 5.6.7.8, 9.10.11.12, ...
2026/10/03 12:01:30 00:11:22:33:44:55(192.168.1.100) 的端口 40000 持续产生PCDN行为（窗口内 31 个对端IP，上行 4.1MiB / 下行 15.2KiB），新增相关IP为: 13.14.15.16, 17.18.19.20
```

## 作为开机自启服务（OpenWrt procd）

新建 `/etc/init.d/pcdn-detect`：

```sh
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/pcdn-detect -i br-lan -c 20 -t 60s
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
