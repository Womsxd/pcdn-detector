// Package firewall 按「设备 MAC + 本地端口 + 协议」对接底层防火墙执行封禁 / 解封。
package firewall

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"pcdn-detect/internal/config"
)

// 防火墙后端。
const (
	fwBackendHook     = "hook"
	fwBackendIptables = "iptables"
	fwBackendNftables = "nftables"
)

// 地址族标签：ban_both=false 时用于区分封禁目标（v4 / v6）。
const (
	familyV4 = "v4"
	familyV6 = "v6"
)

// Firewall 负责按「设备 MAC + 本地端口」封禁 / 解封该设备上的流量。
//
// 三种后端：
//   - hook：由用户提供 ban_cmd / unban_cmd，支持 {mac} {ip} {port} {family} {proto} 占位符（最通用）；
//   - iptables：iptables 与 ip6tables 的指定链按源 MAC 与源端口丢弃（链名由 chain 配置，默认 FORWARD）；
//   - nftables：bridge 族的指定钩子按源 MAC 与源端口丢弃（nftables 仅 bridge/netdev 族支持 MAC
//     匹配）。钩子由 hook 配置（默认 prerouting）：prerouting 能看到所有进入网桥的帧，包括「发给
//     路由器自身 MAC、再被三层路由转发出去」的帧，故对 LAN↔WAN 三层路由场景生效；而 forward 钩子
//     只覆盖纯二层桥接转发的帧，PCDN 这类路由流量不会被命中。链名固定与表名一致。
//
// 封禁地址族由 ban_both 控制：true（默认）同时封禁设备的 IPv4 与 IPv6；
// false 仅封禁触发到的地址族（v4 / v6 各自独立）。
//
// 具体封禁协议随触发该告警的报文（Ban/Unban 的 proto 参数）：UDP 触发只封 UDP、
// TCP 触发只封 TCP。[capture] protocol 决定可封禁的协议范围与 nftables 预置对象：
// "udp"（默认）只准备 UDP；"tcp" 只准备 TCP；"all" 同时准备 UDP 与 TCP（见 capture）。
type Firewall struct {
	backend  string
	banCmd   string
	unbanCmd string
	chain    string // iptables 链名（仅 iptables 后端使用）
	hook     string // nftables 钩子（bridge 族：prerouting / input / forward / output / postrouting）
	table    string // nftables 表名（链名与表名一致）
	set      string // nftables 集合名前缀
	banBoth  bool
	protos   []string // 需封禁的传输层协议（udp，或 udp+tcp）

	// 全 UDP 端口封禁模式（device 级）：fullBan 为真表示启用；
	// fullBanAllow 为触发后仍放行的 UDP 端口（内置常用端口 + 配置追加）。
	fullBan      bool
	fullBanAllow []uint16
	fullBanCmd   string
	fullUnbanCmd string

	// UPnP 拦截（device 级）：upnp 为真表示启用；
	// upnpBlockAll 为真表示「拦截全部进入路由器的 UPnP，仅放行名单设备」（白名单模式），
	// 否则表示「仅拦截名单设备」（黑名单模式）；
	// upnpPorts 为拦截的 UPnP 目的端口（SSDP 1900 / HTTP 控制端口）；
	// upnpChain 为 iptables 后端所用链（默认 INPUT，可配置）；
	// upnpInputHook 为 nftables 后端 UPnP 专用链所用钩子（默认 input，可配置）。
	upnp              bool
	upnpBlockAll      bool
	upnpPorts         []uint16
	upnpChain         string
	upnpInputHook     string
	upnpCmd           string
	upnpUnbanCmd      string
	upnpAllowCmd      string
	upnpDisallow      string
	upnpBlockAllCmd   string
	upnpUnblockAllCmd string

	logger *log.Logger
	run    Runner
}

// banProtos 返回封禁规则覆盖的传输层协议，随 [capture] protocol 变化：
// "udp"（默认）仅 UDP；"tcp" 仅 TCP；"all" 同时封禁 UDP 与 TCP。
func banProtos(protocol string) []string {
	switch protocol {
	case config.ProtoModeTCP:
		return []string{"tcp"}
	case config.ProtoModeAll:
		return []string{"udp", "tcp"}
	default:
		return []string{"udp"}
	}
}

// NewFirewall 根据配置构建执行器并做可用性检查。
// cfg 来自 [firewall]，fb 来自独立的 [full_ban] 配置块，up 来自独立的 [upnp] 配置块；
// upFilter 为 up 解析后的设备过滤方式（由 Config.UPnPFilterValue 得出）；
// protocol 来自 [capture] protocol，决定封禁协议（udp / tcp / all）。
func NewFirewall(cfg config.FirewallConfig, fb config.FullBanConfig, up config.UPnPConfig, upFilter config.UPnPFilter, protocol string, logger *log.Logger) (*Firewall, error) {
	return newFirewallFull(cfg, fb, up, upFilter, protocol, logger, nil)
}

// NewFirewallWithRunner 使用自定义命令执行器构建防火墙（用于测试注入）。
// run 为 nil 时等价于 NewFirewall；不含 UPnP 配置（等价于 [upnp] 未启用）。
func NewFirewallWithRunner(cfg config.FirewallConfig, fb config.FullBanConfig, protocol string, logger *log.Logger, run Runner) (*Firewall, error) {
	return newFirewallFull(cfg, fb, config.UPnPConfig{}, config.UPnPFilter{}, protocol, logger, run)
}

// NewFirewallWithRunnerUPnP 使用自定义命令执行器构建防火墙，并启用 [upnp] 配置（用于测试注入）。
func NewFirewallWithRunnerUPnP(cfg config.FirewallConfig, fb config.FullBanConfig, up config.UPnPConfig, upFilter config.UPnPFilter, protocol string, logger *log.Logger, run Runner) (*Firewall, error) {
	return newFirewallFull(cfg, fb, up, upFilter, protocol, logger, run)
}

// newFirewall 为可测试入口：run 为 nil 时使用真实命令执行（并检查命令是否存在）。
// 不含 UPnP 配置（等价于 [upnp] 未启用）。
func newFirewall(cfg config.FirewallConfig, fb config.FullBanConfig, protocol string, logger *log.Logger, run Runner) (*Firewall, error) {
	return newFirewallFull(cfg, fb, config.UPnPConfig{}, config.UPnPFilter{}, protocol, logger, run)
}

// newFirewallFull 为真实的构建入口：run 为 nil 时使用真实命令执行（并检查命令是否存在）。
func newFirewallFull(cfg config.FirewallConfig, fb config.FullBanConfig, up config.UPnPConfig, upFilter config.UPnPFilter, protocol string, logger *log.Logger, run Runner) (*Firewall, error) {
	f := &Firewall{
		backend:           strings.ToLower(strings.TrimSpace(cfg.Backend)),
		banCmd:            cfg.Hook.BanCmd,
		unbanCmd:          cfg.Hook.UnbanCmd,
		chain:             strings.TrimSpace(cfg.Iptables.Chain),
		hook:              strings.TrimSpace(cfg.Nftables.Hook),
		table:             strings.TrimSpace(cfg.Nftables.Table),
		set:               strings.TrimSpace(cfg.Nftables.Set),
		banBoth:           cfg.BanBothEnabled(),
		protos:            banProtos(protocol),
		fullBan:           fb.FullBanEnabled(),
		fullBanCmd:        fb.Hook.BanCmd,
		fullUnbanCmd:      fb.Hook.UnbanCmd,
		upnp:              up.UPnPEnabled(),
		upnpBlockAll:      up.UPnPEnabled() && upFilter.BlockAll,
		upnpCmd:           up.Hook.BanCmd,
		upnpUnbanCmd:      up.Hook.UnbanCmd,
		upnpAllowCmd:      up.Hook.AllowCmd,
		upnpDisallow:      up.Hook.DisallowCmd,
		upnpBlockAllCmd:   up.Hook.BlockAllCmd,
		upnpUnblockAllCmd: up.Hook.UnblockAllCmd,
		logger:            logger,
		run:               run,
	}
	if f.run == nil {
		f.run = runCommand(time.Duration(cfg.Timeout))
	}
	if f.fullBan {
		allow, err := config.FullBanAllowPorts(fb.Allow)
		if err != nil {
			return nil, err
		}
		f.fullBanAllow = allow
	}
	if f.upnp {
		ports, err := config.ParseUPnPPorts(up.Ports)
		if err != nil {
			return nil, err
		}
		f.upnpPorts = ports
		f.upnpChain = resolveInputChain(cfg.Iptables.InputChain)
	}

	switch f.backend {
	case fwBackendHook:
		if f.banCmd == "" || f.unbanCmd == "" {
			return nil, fmt.Errorf("backend = \"hook\" 需要同时配置 ban_cmd 与 unban_cmd")
		}
		if f.fullBan && (f.fullBanCmd == "" || f.fullUnbanCmd == "") {
			return nil, fmt.Errorf("backend = \"hook\" 启用 full_ban 时需要同时配置 [full_ban] 的 ban_cmd 与 unban_cmd")
		}
		if f.upnp {
			if f.upnpBlockAll {
				// 白名单模式：拦截全部 + 放行名单设备。
				if f.upnpBlockAllCmd == "" || f.upnpUnblockAllCmd == "" {
					return nil, fmt.Errorf("backend = \"hook\" 白名单模式下启用 upnp 时需要同时配置 [upnp] 的 block_all_cmd 与 unblock_all_cmd")
				}
				if len(upFilter.Devices) > 0 && (f.upnpAllowCmd == "" || f.upnpDisallow == "") {
					return nil, fmt.Errorf("backend = \"hook\" 白名单模式下启用 upnp 且有放行设备时需要同时配置 [upnp] 的 allow_cmd 与 disallow_cmd")
				}
			} else if f.upnpCmd == "" || f.upnpUnbanCmd == "" {
				return nil, fmt.Errorf("backend = \"hook\" 黑名单模式下启用 upnp 时需要同时配置 [upnp] 的 ban_cmd 与 unban_cmd")
			}
		}
	case fwBackendIptables:
		if f.chain == "" {
			f.chain = defaultChain
		}
		if run == nil {
			for _, bin := range []string{"iptables", "ip6tables"} {
				if _, err := exec.LookPath(bin); err != nil {
					return nil, fmt.Errorf("未找到 %s 命令：%w", bin, err)
				}
			}
		}
	case fwBackendNftables:
		if f.table == "" {
			f.table = defaultNftTable
		}
		if f.set == "" {
			f.set = defaultNftSet
		}
		hook, err := normalizeNftHook(cfg.Nftables.Hook, nftHookPrerouting)
		if err != nil {
			return nil, err
		}
		f.hook = hook
		if f.hook != nftHookPrerouting {
			f.logger.Printf("警告：nftables hook = %q 非 prerouting；PCDN 属于三层路由流量（目的 MAC 为路由器自身），仅 prerouting 能命中，其他钩子可能只覆盖二层桥接转发、导致封禁失效", f.hook)
		}
		if f.upnp {
			// UPnP 拦截使用独立的 bridge 基础链，钩子由 [firewall.nftables] input_hook 决定（默认 input）。
			ih, err := normalizeNftHook(cfg.Nftables.InputHook, nftHookInput)
			if err != nil {
				return nil, err
			}
			f.upnpInputHook = ih
		}
		if run == nil {
			if _, err := exec.LookPath("nft"); err != nil {
				return nil, fmt.Errorf("未找到 nft 命令：%w", err)
			}
		}
		f.setupNftables()
	default:
		return nil, fmt.Errorf("firewall.backend 无效 %q（可选 hook / iptables / nftables）", cfg.Backend)
	}
	return f, nil
}

// Ban 按触发协议（proto：udp / tcp）封禁某设备 MAC 在该协议下的本地端口。
// ban_both=true 时同时对 IPv4 与 IPv6 生效；否则仅作用于 ip 所属地址族。
func (f *Firewall) Ban(mac, ip string, port uint16, proto string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookRun(f.banCmd, mac, ip, port, proto)
	case fwBackendIptables:
		return f.iptablesSet(true, mac, port, ip, proto)
	case fwBackendNftables:
		return f.nftSet(true, mac, port, ip, proto)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// Unban 按触发协议解封某设备 MAC 在该协议下的本地端口，作用范围与 Ban 一致。
func (f *Firewall) Unban(mac, ip string, port uint16, proto string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookRun(f.unbanCmd, mac, ip, port, proto)
	case fwBackendIptables:
		return f.iptablesSet(false, mac, port, ip, proto)
	case fwBackendNftables:
		return f.nftSet(false, mac, port, ip, proto)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// BanBoth 返回是否同时封禁设备的 IPv4 与 IPv6（由 ban_both 决定）。
func (f *Firewall) BanBoth() bool {
	return f.banBoth
}

// FullBanEnabled 返回是否启用全 UDP 端口封禁模式（[firewall] full_ban != off）。
func (f *Firewall) FullBanEnabled() bool {
	return f.fullBan
}

// FullBanAllowPorts 返回全端口封禁时仍放行的 UDP 端口（内置常用端口 + 配置追加）。
func (f *Firewall) FullBanAllowPorts() []uint16 {
	return f.fullBanAllow
}

// FullBan 对某设备执行全 UDP 端口封禁：除放行的常用 / 白名单端口外，封禁其全部 UDP 流量。
// 该操作为设备级（按源 MAC），对 IPv4 与 IPv6 同时生效。
func (f *Firewall) FullBan(mac string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookFullRun(f.fullBanCmd, mac)
	case fwBackendIptables:
		return f.iptablesFullBan(true, mac)
	case fwBackendNftables:
		return f.nftFullBan(true, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// FullUnban 解除某设备的全 UDP 端口封禁，作用范围与 FullBan 一致。
func (f *Firewall) FullUnban(mac string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookFullRun(f.fullUnbanCmd, mac)
	case fwBackendIptables:
		return f.iptablesFullBan(false, mac)
	case fwBackendNftables:
		return f.nftFullBan(false, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPEnabled 返回是否启用 UPnP 拦截（[upnp] mode != off）。
func (f *Firewall) UPnPEnabled() bool {
	return f.upnp
}

// UPnPPorts 返回 UPnP 拦截覆盖的目的端口（SSDP / HTTP 控制端口）。
func (f *Firewall) UPnPPorts() []uint16 {
	return f.upnpPorts
}

// UPnPBan 对某设备执行 UPnP 拦截：阻断该设备发往路由器的 UPnP 请求
// （目的端口为 upnpPorts，覆盖 UDP 与 TCP）。该操作为设备级（按源 MAC），
// 对 IPv4 与 IPv6 同时生效。
func (f *Firewall) UPnPBan(mac string) error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderUPnPCmd(f.upnpCmd, mac, f.upnpPorts))
	case fwBackendIptables:
		return f.iptablesUPnP(true, mac)
	case fwBackendNftables:
		return f.nftUPnP(true, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPUnban 解除某设备的 UPnP 拦截，作用范围与 UPnPBan 一致。
func (f *Firewall) UPnPUnban(mac string) error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderUPnPCmd(f.upnpUnbanCmd, mac, f.upnpPorts))
	case fwBackendIptables:
		return f.iptablesUPnP(false, mac)
	case fwBackendNftables:
		return f.nftUPnP(false, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPBlockAll 拦截**全部**进入路由器的 UPnP（白名单模式）：命中目的端口的 UPnP 一律丢弃，
// 再由 UPnPAllow 为名单设备放行。该操作为全局（与设备无关）。
func (f *Firewall) UPnPBlockAll() error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderUPnPAllCmd(f.upnpBlockAllCmd, f.upnpPorts))
	case fwBackendIptables:
		return f.iptablesUPnPBlockAll(true)
	case fwBackendNftables:
		// nftables 的全量拦截规则在 setupNftables 中随链一并创建（退出时随表删除），此处无需操作。
		return nil
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPUnblockAll 解除 UPnPBlockAll 的全量拦截，作用范围与 UPnPBlockAll 一致。
func (f *Firewall) UPnPUnblockAll() error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderUPnPAllCmd(f.upnpUnblockAllCmd, f.upnpPorts))
	case fwBackendIptables:
		return f.iptablesUPnPBlockAll(false)
	case fwBackendNftables:
		return nil
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPAllow 为某设备放行 UPnP（白名单模式）：该设备发往路由器 UPnP 目的端口的流量将被接受，
// 优先于 UPnPBlockAll 的全量丢弃。作用范围与 UPnPBan 一致（按源 MAC，v4/v6 同时生效）。
func (f *Firewall) UPnPAllow(mac string) error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderUPnPCmd(f.upnpAllowCmd, mac, f.upnpPorts))
	case fwBackendIptables:
		return f.iptablesUPnPAllow(true, mac)
	case fwBackendNftables:
		return f.nftUPnPAllow(true, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPDisallow 取消某设备的 UPnP 放行，作用范围与 UPnPAllow 一致。
func (f *Firewall) UPnPDisallow(mac string) error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderUPnPCmd(f.upnpDisallow, mac, f.upnpPorts))
	case fwBackendIptables:
		return f.iptablesUPnPAllow(false, mac)
	case fwBackendNftables:
		return f.nftUPnPAllow(false, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// targetFamilies 返回本次操作应作用到的地址族：
// ban_both=true 时同时包含 v4/v6；否则仅返回 ip 所属地址族。
func (f *Firewall) targetFamilies(ip string) []string {
	if f.banBoth {
		return []string{familyV4, familyV6}
	}
	return []string{AddrFamily(ip)}
}

// Cleanup 清除本程序添加的防火墙对象，应在退出前调用。
//   - nftables：删除整张表，连带链、集合与规则一并清除；
//   - iptables：规则由 Blocker 逐条解封，无需在此处理；
//   - hook：由用户提供的 unban_cmd 负责。
func (f *Firewall) Cleanup() {
	if f.backend != fwBackendNftables {
		return
	}
	if err := f.run("nft", fmt.Sprintf("delete table bridge %s", f.table)); err != nil {
		// 表可能已被外部清理，失败仅告警，不致命。
		f.logger.Printf("退出时清除 nftables 表 %s 失败：%v", f.table, err)
		return
	}
	f.logger.Printf("退出时已清除 nftables 表 %s", f.table)
}

// Describe 返回后端描述，用于启动日志。
func (f *Firewall) Describe() string {
	scope := "同时封禁 v4/v6"
	if !f.banBoth {
		scope = "按地址族单独封禁"
	}
	proto := f.protoDesc()
	var desc string
	switch f.backend {
	case fwBackendHook:
		desc = fmt.Sprintf("自定义命令（hook，封禁 %s，%s）", proto, scope)
	case fwBackendIptables:
		desc = fmt.Sprintf("iptables/ip6tables（链 %s，按源 MAC + %s 源端口丢弃，%s）", f.chain, proto, scope)
	case fwBackendNftables:
		desc = fmt.Sprintf("nftables（bridge %s 表，%s 钩子，集合 %s_v4/%s_v6，按源 MAC + %s 源端口丢弃，%s）", f.table, f.hook, f.set, f.set, proto, scope)
	default:
		return f.backend
	}
	if f.fullBan {
		desc += fmt.Sprintf("；全 UDP 端口封禁已启用（放行端口：%s）", portsCSV(f.fullBanAllow))
	}
	if f.upnp {
		desc += fmt.Sprintf("；UPnP 拦截已启用（目的端口：%s，%s，%s）", portsCSV(f.upnpPorts), f.upnpLocation(), f.upnpScope())
	}
	return desc
}

// upnpScope 返回 UPnP 拦截范围的展示名，用于启动日志。
func (f *Firewall) upnpScope() string {
	if f.upnpBlockAll {
		return "拦截全部 + 放行名单"
	}
	return "仅拦截名单设备"
}

// upnpLocation 返回 UPnP 拦截所用链/钩子的展示名，用于启动日志。
func (f *Firewall) upnpLocation() string {
	switch f.backend {
	case fwBackendIptables:
		return "链 " + f.upnpChain
	case fwBackendNftables:
		return "钩子 " + f.upnpInputHook
	}
	return "hook 命令"
}

// protoDesc 返回封禁协议的展示名（如 "UDP"、"UDP/TCP"），用于日志。
func (f *Firewall) protoDesc() string {
	return strings.ToUpper(strings.Join(f.protos, "/"))
}

// AddrFamily 由设备 IP 判断地址族：含 ":" 视为 IPv6，否则视为 IPv4。
func AddrFamily(ip string) string {
	if strings.Contains(ip, ":") {
		return familyV6
	}
	return familyV4
}

// portsCSV 把端口列表渲染为逗号分隔字符串（如 "53,67,68,123"）。
func portsCSV(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}
