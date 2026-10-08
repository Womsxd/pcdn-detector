package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
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

// commandRunner 执行一条外部命令；返回错误表示执行失败。
type commandRunner func(name string, args ...string) error

// Firewall 负责按「设备 MAC + 本地端口」封禁 / 解封该设备上的流量。
//
// 三种后端：
//   - hook：由用户提供 ban_cmd / unban_cmd，支持 {mac} {ip} {port} {family} {proto} 占位符（最通用）；
//   - iptables：iptables 与 ip6tables 的 FORWARD 链按源 MAC 与源端口丢弃；
//   - nftables：bridge 族按源 MAC 与源端口丢弃（nftables 仅 bridge/netdev 族支持 MAC 匹配）。
//
// 封禁地址族由 ban_both 控制：true（默认）同时封禁设备的 IPv4 与 IPv6；
// false 仅封禁触发到的地址族（v4 / v6 各自独立）。
//
// 具体封禁协议随触发该告警的报文（Ban/Unban 的 proto 参数）：UDP 触发只封 UDP、
// TCP 触发只封 TCP。[capture] udp_only 决定可封禁的协议范围与 nftables 预置对象：
// true（默认）只准备 UDP；false 时同时准备 UDP 与 TCP（抓包层也会统计 TCP，见 capture.go）。
type Firewall struct {
	backend  string
	banCmd   string
	unbanCmd string
	chain    string
	table    string
	set      string
	banBoth  bool
	protos   []string // 需封禁的传输层协议（udp，或 udp+tcp）
	logger   *log.Logger
	run      commandRunner
}

// banProtos 返回封禁规则覆盖的传输层协议：
// udp_only=true（默认）仅 UDP；udp_only=false 时同时封禁 UDP 与 TCP。
func banProtos(udpOnly bool) []string {
	if udpOnly {
		return []string{"udp"}
	}
	return []string{"udp", "tcp"}
}

// NewFirewall 根据配置构建执行器并做可用性检查。
// udpOnly 来自 [capture] udp_only，决定封禁协议（true 仅 UDP，false 为 UDP+TCP）。
func NewFirewall(cfg FirewallConfig, udpOnly bool, logger *log.Logger) (*Firewall, error) {
	return newFirewall(cfg, udpOnly, logger, nil)
}

// newFirewall 为可测试入口：run 为 nil 时使用真实命令执行（并检查命令是否存在）。
func newFirewall(cfg FirewallConfig, udpOnly bool, logger *log.Logger, run commandRunner) (*Firewall, error) {
	f := &Firewall{
		backend:  strings.ToLower(strings.TrimSpace(cfg.Backend)),
		banCmd:   cfg.BanCmd,
		unbanCmd: cfg.UnbanCmd,
		chain:    strings.TrimSpace(cfg.Chain),
		table:    strings.TrimSpace(cfg.Table),
		set:      strings.TrimSpace(cfg.Set),
		banBoth:  cfg.banBothEnabled(),
		protos:   banProtos(udpOnly),
		logger:   logger,
		run:      run,
	}
	if f.run == nil {
		f.run = runCommand(time.Duration(cfg.Timeout))
	}

	switch f.backend {
	case fwBackendHook:
		if f.banCmd == "" || f.unbanCmd == "" {
			return nil, fmt.Errorf("backend = \"hook\" 需要同时配置 ban_cmd 与 unban_cmd")
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
			f.chain = "forward"
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
// 这些对象可能已存在，失败仅记录警告，不致命。
func (f *Firewall) setupNftables() {
	stmts := []string{
		fmt.Sprintf("add table bridge %s", f.table),
		fmt.Sprintf("add chain bridge %s %s { type filter hook forward priority -150 ; }", f.table, f.chain),
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

// targetFamilies 返回本次操作应作用到的地址族：
// ban_both=true 时同时包含 v4/v6；否则仅返回 ip 所属地址族。
func (f *Firewall) targetFamilies(ip string) []string {
	if f.banBoth {
		return []string{familyV4, familyV6}
	}
	return []string{addrFamily(ip)}
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
	switch f.backend {
	case fwBackendHook:
		return fmt.Sprintf("自定义命令（hook，封禁 %s，%s）", proto, scope)
	case fwBackendIptables:
		return fmt.Sprintf("iptables/ip6tables（链 %s，按源 MAC + %s 源端口丢弃，%s）", f.chain, proto, scope)
	case fwBackendNftables:
		return fmt.Sprintf("nftables（bridge %s 集合 %s_v4/%s_v6，按源 MAC + %s 源端口丢弃，%s）", f.table, f.set, f.set, proto, scope)
	}
	return f.backend
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

// addrFamily 由设备 IP 判断地址族：含 ":" 视为 IPv6，否则视为 IPv4。
func addrFamily(ip string) string {
	if strings.Contains(ip, ":") {
		return familyV6
	}
	return familyV4
}

// runCommand 返回带超时的真实命令执行器。
func runCommand(timeout time.Duration) commandRunner {
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
