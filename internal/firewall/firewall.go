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
//   - hook：由用户提供**单条命令模板**（hookCmd），由 {action} 区分动作，
//     支持 {action} {mac} {ip} {port} {family} {proto} 占位符（最通用，调用方自写 sh 包装分发）；
//   - iptables：iptables 与 ip6tables 的专用链（PCDN_DETECT / PCDN_DETECT_UPNP）按源 MAC 与源端口
//     丢弃；chain / input_chain 只是跳转插入点（默认 FORWARD / INPUT）；
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
	hookCmd  string // [firewall.hook] 单条命令模板（{action} ban/unban ...）
	chain    string // iptables 跳转插入点（仅 iptables 后端使用）
	banChain string // iptables 端口封禁专用链名（规则实际落点）
	hook     string // nftables 钩子（bridge 族：prerouting / input / forward / output / postrouting）
	table    string // nftables 表名（链名与表名一致）
	set      string // nftables 集合名前缀
	banBoth  bool
	protos   []string // 需封禁的传输层协议（udp，或 udp+tcp）

	// 全 UDP 端口封禁模式（device 级）：fullBan 为真表示启用；
	// fullBanAllow 为触发后仍放行的 UDP 端口（内置常用端口 + 配置追加）；
	// fullBanHookCmd 为 [full_ban.hook] 的单条命令模板（{action} ban/unban {mac} {ports}）。
	fullBan        bool
	fullBanAllow   []uint16
	fullBanHookCmd string

	// UPnP 拦截（device 级）：upnp 为真表示启用；
	// upnpBlockAll 为真表示「拦截全部进入路由器的 UPnP，仅放行名单设备」（白名单模式），
	// 否则表示「仅拦截名单设备」（黑名单模式）；
	// upnpPorts 为拦截的 UPnP 目的端口（SSDP 1900 / HTTP 控制端口）；
	// upnpChain 为 iptables 后端的跳转插入点（默认 INPUT，可配置；规则落在 PCDN_DETECT_UPNP）；
	// upnpInputHook 为 nftables 后端 UPnP 专用链所用钩子（默认 input，可配置）；
	// upnpHookCmd 为 [upnp.hook] 的单条命令模板（{action} {mac} {ports}）。
	upnp          bool
	upnpBlockAll  bool
	upnpPorts     []uint16
	upnpChain     string
	upnpRuleChain string // iptables UPnP 专用链名（规则实际落点）
	upnpInputHook string
	upnpHookCmd   string

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
		backend:        strings.ToLower(strings.TrimSpace(cfg.Backend)),
		hookCmd:        cfg.Hook.Cmd,
		chain:          strings.TrimSpace(cfg.Iptables.Chain),
		hook:           strings.TrimSpace(cfg.Nftables.Hook),
		table:          strings.TrimSpace(cfg.Nftables.Table),
		set:            strings.TrimSpace(cfg.Nftables.Set),
		banBoth:        cfg.BanBothEnabled(),
		protos:         banProtos(protocol),
		fullBan:        fb.FullBanEnabled(),
		fullBanHookCmd: fb.Hook.Cmd,
		upnp:           up.UPnPEnabled(),
		upnpBlockAll:   up.UPnPEnabled() && upFilter.BlockAll,
		upnpHookCmd:    up.Hook.Cmd,
		logger:         logger,
		run:            run,
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
	}

	switch f.backend {
	case fwBackendHook:
		if f.hookCmd == "" {
			return nil, fmt.Errorf("backend = \"hook\" 需要配置 [firewall.hook] 的 cmd")
		}
		if f.fullBan && f.fullBanHookCmd == "" {
			return nil, fmt.Errorf("backend = \"hook\" 启用 full_ban 时需要配置 [full_ban.hook] 的 cmd")
		}
		if f.upnp && f.upnpHookCmd == "" {
			return nil, fmt.Errorf("backend = \"hook\" 启用 upnp 时需要配置 [upnp.hook] 的 cmd")
		}
	case fwBackendIptables:
		if f.chain == "" {
			f.chain = defaultChain
		}
		// UPnP 拦截的跳转插入点：即使本次未启用也要解析，用于清理上次运行可能残留的专用链。
		f.upnpChain = resolveInputChain(cfg.Iptables.InputChain)
		// 专用链名可自定义；留空用默认值。校验避免与跳转链重名（否则启动清空会误删用户规则）。
		f.banChain = strings.TrimSpace(cfg.Iptables.BanChain)
		if f.banChain == "" {
			f.banChain = defaultIptablesBanChain
		}
		f.upnpRuleChain = strings.TrimSpace(cfg.Iptables.UPnPChain)
		if f.upnpRuleChain == "" {
			f.upnpRuleChain = defaultIptablesUPnPChain
		}
		if err := validateIptablesChains(f.chain, f.upnpChain, f.banChain, f.upnpRuleChain); err != nil {
			return nil, err
		}
		if run == nil {
			for _, bin := range []string{"iptables", "ip6tables"} {
				if _, err := exec.LookPath(bin); err != nil {
					return nil, fmt.Errorf("未找到 %s 命令：%w", bin, err)
				}
			}
		}
		f.setupIptables()
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
		return f.hookRun("ban", mac, ip, port, proto)
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
		return f.hookRun("unban", mac, ip, port, proto)
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
// 该操作为设备级（按源 MAC），对 IPv4 与 IPv6 同时生效；ip 为该设备本次触发时的 IP
// （仅 hook 后端用于 {ip} 占位符，其余后端忽略）。
func (f *Firewall) FullBan(mac, ip string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookFullRun("ban", mac, ip)
	case fwBackendIptables:
		return f.iptablesFullBan(true, mac)
	case fwBackendNftables:
		return f.nftFullBan(true, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// FullUnban 解除某设备的全 UDP 端口封禁，作用范围与 FullBan 一致。
func (f *Firewall) FullUnban(mac, ip string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookFullRun("unban", mac, ip)
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
// 对 IPv4 与 IPv6 同时生效；ip 为该设备已知 IP（仅 hook 后端用于 {ip} 占位符）。
func (f *Firewall) UPnPBan(mac, ip string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookUPnPRun("ban", mac, ip)
	case fwBackendIptables:
		return f.iptablesUPnP(true, mac)
	case fwBackendNftables:
		return f.nftUPnP(true, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPUnban 解除某设备的 UPnP 拦截，作用范围与 UPnPBan 一致。
func (f *Firewall) UPnPUnban(mac, ip string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookUPnPRun("unban", mac, ip)
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
		return f.hookUPnPRun("block-all", "", "")
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
		return f.hookUPnPRun("unblock-all", "", "")
	case fwBackendIptables:
		return f.iptablesUPnPBlockAll(false)
	case fwBackendNftables:
		return nil
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPAllow 为某设备放行 UPnP（白名单模式）：该设备发往路由器 UPnP 目的端口的流量将被接受，
// 优先于 UPnPBlockAll 的全量丢弃。作用范围与 UPnPBan 一致（按源 MAC，v4/v6 同时生效）。
func (f *Firewall) UPnPAllow(mac, ip string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookUPnPRun("allow", mac, ip)
	case fwBackendIptables:
		return f.iptablesUPnPAllow(true, mac)
	case fwBackendNftables:
		return f.nftUPnPAllow(true, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// UPnPDisallow 取消某设备的 UPnP 放行，作用范围与 UPnPAllow 一致。
func (f *Firewall) UPnPDisallow(mac, ip string) error {
	switch f.backend {
	case fwBackendHook:
		return f.hookUPnPRun("disallow", mac, ip)
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
//   - iptables：删除跳转与专用链（规则全在专用链内）；
//   - hook：由用户提供的 unban_cmd 负责。
func (f *Firewall) Cleanup() {
	switch f.backend {
	case fwBackendNftables:
		if err := f.run("nft", fmt.Sprintf("delete table bridge %s", f.table)); err != nil {
			// 表可能已被外部清理，失败仅告警，不致命。
			f.logger.Printf("退出时清除 nftables 表 %s 失败：%v", f.table, err)
			return
		}
		f.logger.Printf("退出时已清除 nftables 表 %s", f.table)
	case fwBackendIptables:
		f.cleanupIptables()
		f.logger.Printf("退出时已清理 iptables 专用链 %s / %s", f.banChain, f.upnpRuleChain)
	}
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
		desc = fmt.Sprintf("iptables/ip6tables（%s → %s，按源 MAC + %s 源端口丢弃，%s）", f.chain, f.banChain, proto, scope)
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
