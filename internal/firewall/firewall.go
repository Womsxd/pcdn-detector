// Package firewall 按「设备 MAC + 本地端口 + 协议」对接底层防火墙执行封禁 / 解封。
package firewall

import (
	"context"
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

// Runner 执行一条外部命令；返回错误表示执行失败。供测试注入自定义实现。
type Runner func(name string, args ...string) error

// Firewall 负责按「设备 MAC + 本地端口」封禁 / 解封该设备上的流量。
//
// 三种后端：
//   - hook：由用户提供 ban_cmd / unban_cmd，支持 {mac} {ip} {port} {family} {proto} 占位符（最通用）；
//   - iptables：iptables 与 ip6tables 的 FORWARD 链按源 MAC 与源端口丢弃；
//   - nftables：bridge 族的 prerouting 钩子按源 MAC 与源端口丢弃（nftables 仅 bridge/netdev
//     族支持 MAC 匹配；prerouting 能看到所有进入网桥的帧，包括「发给路由器自身 MAC、再被三层
//     路由转发出去」的帧，故对 LAN↔WAN 三层路由场景同样生效——用 forward 钩子则只覆盖纯二层
//     桥接转发的帧，PCDN 这类路由流量不会被命中）。
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
	chain    string
	table    string
	set      string
	banBoth  bool
	protos   []string // 需封禁的传输层协议（udp，或 udp+tcp）

	// 全 UDP 端口封禁模式（device 级）：fullBan 为真表示启用；
	// fullBanAllow 为触发后仍放行的 UDP 端口（内置常用端口 + 配置追加）。
	fullBan      bool
	fullBanAllow []uint16
	fullBanCmd   string
	fullUnbanCmd string

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
// cfg 来自 [firewall]，fb 来自独立的 [full_ban] 配置块；
// protocol 来自 [capture] protocol，决定封禁协议（udp / tcp / all）。
func NewFirewall(cfg config.FirewallConfig, fb config.FullBanConfig, protocol string, logger *log.Logger) (*Firewall, error) {
	return newFirewall(cfg, fb, protocol, logger, nil)
}

// NewFirewallWithRunner 使用自定义命令执行器构建防火墙（用于测试注入）。
// run 为 nil 时等价于 NewFirewall。
func NewFirewallWithRunner(cfg config.FirewallConfig, fb config.FullBanConfig, protocol string, logger *log.Logger, run Runner) (*Firewall, error) {
	return newFirewall(cfg, fb, protocol, logger, run)
}

// newFirewall 为可测试入口：run 为 nil 时使用真实命令执行（并检查命令是否存在）。
func newFirewall(cfg config.FirewallConfig, fb config.FullBanConfig, protocol string, logger *log.Logger, run Runner) (*Firewall, error) {
	f := &Firewall{
		backend:      strings.ToLower(strings.TrimSpace(cfg.Backend)),
		banCmd:       cfg.BanCmd,
		unbanCmd:     cfg.UnbanCmd,
		chain:        strings.TrimSpace(cfg.Chain),
		table:        strings.TrimSpace(cfg.Table),
		set:          strings.TrimSpace(cfg.Set),
		banBoth:      cfg.BanBothEnabled(),
		protos:       banProtos(protocol),
		fullBan:      fb.FullBanEnabled(),
		fullBanCmd:   fb.BanCmd,
		fullUnbanCmd: fb.UnbanCmd,
		logger:       logger,
		run:          run,
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

	switch f.backend {
	case fwBackendHook:
		if f.banCmd == "" || f.unbanCmd == "" {
			return nil, fmt.Errorf("backend = \"hook\" 需要同时配置 ban_cmd 与 unban_cmd")
		}
		if f.fullBan && (f.fullBanCmd == "" || f.fullUnbanCmd == "") {
			return nil, fmt.Errorf("backend = \"hook\" 启用 full_ban 时需要同时配置 [full_ban] 的 ban_cmd 与 unban_cmd")
		}
	case fwBackendIptables:
		if f.chain == "" {
			f.chain = "FORWARD"
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
			f.table = "pcdn_detect"
		}
		if f.set == "" {
			f.set = "banned"
		}
		if f.chain == "" {
			f.chain = "prerouting"
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

// setupNftables 初始化 bridge 族的表/链，以及按「地址族 + 协议」拆分的拼接集合与各自的丢弃规则。
// 集合为拼接（concatenation）类型，元素形如 `aa:bb:cc:dd:ee:ff . 40000`；
// 同名集合按 f.protos 与 v4/v6 展开为 <set>_<family>_<proto>（如 banned_v4_udp），
// 使 UDP 与 TCP 各自独立封禁（UDP 触发只影响 UDP 集合，TCP 触发只影响 TCP 集合）。
//
// 基础链挂到 bridge 族的 prerouting 钩子（而非 forward）：prerouting 能看到所有进入网桥的帧，
// 既包含纯二层桥接转发的帧，也包含「发给路由器自身 MAC、随后被三层路由转发出去」的帧。
// PCDN 是设备↔公网的路由流量，其帧的目标 MAC 为路由器 br-lan，走的是 prerouting/input 而非
// forward，因此用 forward 钩子时规则永不命中、封禁形同虚设。
// 这些对象可能已存在，失败仅记录警告，不致命。
func (f *Firewall) setupNftables() {
	stmts := []string{
		fmt.Sprintf("add table bridge %s", f.table),
		fmt.Sprintf("add chain bridge %s %s { type filter hook prerouting priority -150 ; }", f.table, f.chain),
	}
	for _, family := range []string{familyV4, familyV6} {
		for _, proto := range f.protos {
			stmts = append(stmts, fmt.Sprintf("add set bridge %s %s { type ether_addr . inet_service ; }", f.table, f.nftSetName(family, proto)))
		}
	}
	for _, proto := range f.protos {
		stmts = append(stmts,
			fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol %s ether saddr . %s sport @%s drop", f.table, f.chain, proto, proto, f.nftSetName(familyV4, proto)),
			fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr %s ether saddr . %s sport @%s drop", f.table, f.chain, proto, proto, f.nftSetName(familyV6, proto)),
		)
	}
	// 全 UDP 端口封禁：以「设备 MAC 集合 + 放行端口集合」实现，
	// 规则顺序须为「先放行白名单端口、再整体丢弃」，故 accept 规则先于 drop 规则加入。
	if f.fullBan {
		stmts = append(stmts,
			fmt.Sprintf("add set bridge %s %s { type ether_addr ; }", f.table, f.fullBanMacsSet()),
			fmt.Sprintf("add set bridge %s %s { type inet_service ; }", f.table, f.fullBanAllowSet()),
		)
		if len(f.fullBanAllow) > 0 {
			stmts = append(stmts,
				fmt.Sprintf("add element bridge %s %s { %s }", f.table, f.fullBanAllowSet(), portsCSV(f.fullBanAllow)),
			)
		}
		stmts = append(stmts,
			fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol udp ether saddr @%s udp dport @%s accept", f.table, f.chain, f.fullBanMacsSet(), f.fullBanAllowSet()),
			fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol udp ether saddr @%s drop", f.table, f.chain, f.fullBanMacsSet()),
			fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr udp ether saddr @%s udp dport @%s accept", f.table, f.chain, f.fullBanMacsSet(), f.fullBanAllowSet()),
			fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr udp ether saddr @%s drop", f.table, f.chain, f.fullBanMacsSet()),
		)
	}
	for _, s := range stmts {
		if err := f.run("nft", s); err != nil {
			f.logger.Printf("警告：nft 初始化语句失败（可能已存在）：%v", err)
		}
	}
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
		return f.run("sh", "-c", renderFullBanCmd(f.fullBanCmd, mac, f.fullBanAllow))
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
		return f.run("sh", "-c", renderFullBanCmd(f.fullUnbanCmd, mac, f.fullBanAllow))
	case fwBackendIptables:
		return f.iptablesFullBan(false, mac)
	case fwBackendNftables:
		return f.nftFullBan(false, mac)
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// fullBanMacsSet / fullBanAllowSet 返回 nftables 中全端口封禁所用的集合名
// （分别为「被全封禁的设备 MAC 集合」与「仍放行的 UDP 端口集合」）。
func (f *Firewall) fullBanMacsSet() string  { return f.set + "_fullban_macs" }
func (f *Firewall) fullBanAllowSet() string { return f.set + "_fullban_allow" }

// iptablesFullBan 在 iptables（v4）与 ip6tables（v6）的链上按源 MAC 对全部 UDP 流量封禁 / 解封：
// 先放行允许端口（--dports 多端口匹配，ACCEPT），再丢弃其余 UDP（DROP）。
// 插入顺序须为「先 DROP 再 ACCEPT」，使 ACCEPT 位于 DROP 之上而优先生效。
func (f *Firewall) iptablesFullBan(ban bool, mac string) error {
	base := []string{"-m", "mac", "--mac-source", mac, "-p", "udp"}
	dropRule := append(append([]string{}, base...), "-j", "DROP")
	rules := [][]string{dropRule}
	if len(f.fullBanAllow) > 0 {
		accept := append(append([]string{}, base...),
			"-m", "multiport", "--dports", portsCSV(f.fullBanAllow), "-j", "ACCEPT")
		rules = append(rules, accept)
	}

	var firstErr error
	for _, bin := range []string{"iptables", "ip6tables"} {
		for _, rule := range rules {
			if ban {
				check := append([]string{"-C", f.chain}, rule...)
				if f.run(bin, check...) == nil {
					continue // 规则已存在
				}
				insert := append([]string{"-I", f.chain}, rule...)
				if err := f.run(bin, insert...); err != nil && firstErr == nil {
					firstErr = err
				}
			} else {
				del := append([]string{"-D", f.chain}, rule...)
				if err := f.run(bin, del...); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

// nftFullBan 在 nftables 的「被全封禁设备 MAC 集合」中添加 / 删除元素（bridge 族）。
func (f *Firewall) nftFullBan(ban bool, mac string) error {
	verb := "add"
	if !ban {
		verb = "delete"
	}
	cmd := fmt.Sprintf("%s element bridge %s %s { %s }", verb, f.table, f.fullBanMacsSet(), mac)
	return f.run("nft", cmd)
}

// targetFamilies 返回本次操作应作用到的地址族：
// ban_both=true 时同时包含 v4/v6；否则仅返回 ip 所属地址族。
func (f *Firewall) targetFamilies(ip string) []string {
	if f.banBoth {
		return []string{familyV4, familyV6}
	}
	return []string{AddrFamily(ip)}
}

// nftSetName 返回「地址族 + 协议」对应的 nftables 集合名（如 banned_v4_udp / banned_v6_tcp）。
func (f *Firewall) nftSetName(family, proto string) string {
	return f.set + "_" + family + "_" + proto
}

// hookRun 运行 hook 命令模板。ban_both=true 时对 v4/v6 各执行一次，用 {family} 区分地址族；
// {proto} 为该次封禁的触发协议。若模板不含对应占位符，则该维度会重复执行同一命令，需确保命令幂等。
func (f *Firewall) hookRun(tpl, mac, ip string, port uint16, proto string) error {
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		if err := f.run("sh", "-c", renderCmd(tpl, mac, ip, port, family, proto)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// nftSet 在「地址族 + 协议」对应的 nftables 集合中按「MAC . 端口」添加 / 删除元素。
func (f *Firewall) nftSet(ban bool, mac string, port uint16, ip, proto string) error {
	verb := "add"
	if !ban {
		verb = "delete"
	}
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		cmd := fmt.Sprintf("%s element bridge %s %s { %s . %d }", verb, f.table, f.nftSetName(family, proto), mac, port)
		if err := f.run("nft", cmd); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// iptablesSet 在 iptables（v4）/ ip6tables（v6）的链上，按源 MAC + 源端口封禁/解封该触发协议。
// 封禁前先用 -C 检查，避免重复插入。
func (f *Firewall) iptablesSet(ban bool, mac string, port uint16, ip, proto string) error {
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		bin := "iptables"
		if family == familyV6 {
			bin = "ip6tables"
		}
		rule := []string{"-m", "mac", "--mac-source", mac, "-p", proto, "--sport", strconv.Itoa(int(port)), "-j", "DROP"}
		var err error
		if ban {
			check := append([]string{"-C", f.chain}, rule...)
			if f.run(bin, check...) == nil {
				continue // 规则已存在
			}
			insert := append([]string{"-I", f.chain}, rule...)
			err = f.run(bin, insert...)
		} else {
			del := append([]string{"-D", f.chain}, rule...)
			err = f.run(bin, del...)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
		desc = fmt.Sprintf("nftables（bridge %s 集合 %s_v4/%s_v6，按源 MAC + %s 源端口丢弃，%s）", f.table, f.set, f.set, proto, scope)
	default:
		return f.backend
	}
	if f.fullBan {
		desc += fmt.Sprintf("；全 UDP 端口封禁已启用（放行端口：%s）", portsCSV(f.fullBanAllow))
	}
	return desc
}

// protoDesc 返回封禁协议的展示名（如 "UDP"、"UDP/TCP"），用于日志。
func (f *Firewall) protoDesc() string {
	return strings.ToUpper(strings.Join(f.protos, "/"))
}

// renderCmd 替换 hook 命令中的占位符。
func renderCmd(tpl, mac, ip string, port uint16, family, proto string) string {
	return strings.NewReplacer(
		"{mac}", mac,
		"{ip}", ip,
		"{port}", strconv.Itoa(int(port)),
		"{family}", family,
		"{proto}", proto,
	).Replace(tpl)
}

// renderFullBanCmd 替换全端口封禁 hook 命令中的占位符：{mac} 与 {ports}（放行端口逗号列表）。
func renderFullBanCmd(tpl, mac string, ports []uint16) string {
	return strings.NewReplacer(
		"{mac}", mac,
		"{ports}", portsCSV(ports),
	).Replace(tpl)
}

// portsCSV 把端口列表渲染为逗号分隔字符串（如 "53,67,68,123"）。
func portsCSV(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

// AddrFamily 由设备 IP 判断地址族：含 ":" 视为 IPv6，否则视为 IPv4。
func AddrFamily(ip string) string {
	if strings.Contains(ip, ":") {
		return familyV6
	}
	return familyV4
}

// runCommand 返回带超时的真实命令执行器。
func runCommand(timeout time.Duration) Runner {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s：%v（输出：%s）", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
