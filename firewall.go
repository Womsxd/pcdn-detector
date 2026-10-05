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

// commandRunner 执行一条外部命令；返回错误表示执行失败。
type commandRunner func(name string, args ...string) error

// Firewall 负责按「设备 MAC + 本地端口」封禁 / 解封该设备上的 UDP 流量。
//
// 三种后端：
//   - hook：由用户提供 ban_cmd / unban_cmd，支持 {mac} {ip} {port} 占位符（最通用）；
//   - iptables：iptables 与 ip6tables 的 FORWARD 链按源 MAC 与 UDP 源端口丢弃；
//   - nftables：bridge 族按源 MAC 与 UDP 源端口丢弃（nftables 仅 bridge/netdev 族支持 MAC 匹配）。
type Firewall struct {
	backend  string
	banCmd   string
	unbanCmd string
	chain    string
	table    string
	set      string
	logger   *log.Logger
	run      commandRunner
}

// NewFirewall 根据配置构建执行器并做可用性检查。
func NewFirewall(cfg FirewallConfig, logger *log.Logger) (*Firewall, error) {
	return newFirewall(cfg, logger, nil)
}

// newFirewall 为可测试入口：run 为 nil 时使用真实命令执行（并检查命令是否存在）。
func newFirewall(cfg FirewallConfig, logger *log.Logger, run commandRunner) (*Firewall, error) {
	f := &Firewall{
		backend:  strings.ToLower(strings.TrimSpace(cfg.Backend)),
		banCmd:   cfg.BanCmd,
		unbanCmd: cfg.UnbanCmd,
		chain:    strings.TrimSpace(cfg.Chain),
		table:    strings.TrimSpace(cfg.Table),
		set:      strings.TrimSpace(cfg.Set),
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

// setupNftables 初始化 bridge 族的表/链/集合，以及按「源 MAC . UDP 源端口」丢弃的规则。
// 集合为拼接（concatenation）类型，元素形如 `aa:bb:cc:dd:ee:ff . 40000`。
// 这些对象可能已存在，失败仅记录警告，不致命。
func (f *Firewall) setupNftables() {
	stmts := []string{
		fmt.Sprintf("add table bridge %s", f.table),
		fmt.Sprintf("add chain bridge %s %s { type filter hook forward priority -150 ; }", f.table, f.chain),
		fmt.Sprintf("add set bridge %s %s { type ether_addr . inet_service ; }", f.table, f.set),
		fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol udp ether saddr . udp sport @%s drop", f.table, f.chain, f.set),
		fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr udp ether saddr . udp sport @%s drop", f.table, f.chain, f.set),
	}
	for _, s := range stmts {
		if err := f.run("nft", s); err != nil {
			f.logger.Printf("警告：nft 初始化语句失败（可能已存在）：%v", err)
		}
	}
}

// Ban 封禁某设备 MAC 上的 UDP 端口。
func (f *Firewall) Ban(mac, ip string, port uint16) error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderCmd(f.banCmd, mac, ip, port))
	case fwBackendIptables:
		return f.iptablesSet(true, mac, port)
	case fwBackendNftables:
		return f.run("nft", fmt.Sprintf("add element bridge %s %s { %s . %d }", f.table, f.set, mac, port))
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// Unban 解封某设备 MAC 上的 UDP 端口。
func (f *Firewall) Unban(mac, ip string, port uint16) error {
	switch f.backend {
	case fwBackendHook:
		return f.run("sh", "-c", renderCmd(f.unbanCmd, mac, ip, port))
	case fwBackendIptables:
		return f.iptablesSet(false, mac, port)
	case fwBackendNftables:
		return f.run("nft", fmt.Sprintf("delete element bridge %s %s { %s . %d }", f.table, f.set, mac, port))
	}
	return fmt.Errorf("未知后端 %q", f.backend)
}

// iptablesSet 在 iptables 与 ip6tables 的 FORWARD 链上，按源 MAC + UDP 源端口封禁/解封。
// 封禁前先用 -C 检查，避免重复插入。
func (f *Firewall) iptablesSet(ban bool, mac string, port uint16) error {
	var firstErr error
	for _, bin := range []string{"iptables", "ip6tables"} {
		rule := []string{"-m", "mac", "--mac-source", mac, "-p", "udp", "--sport", strconv.Itoa(int(port)), "-j", "DROP"}
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
	switch f.backend {
	case fwBackendHook:
		return "自定义命令（hook）"
	case fwBackendIptables:
		return fmt.Sprintf("iptables/ip6tables（链 %s，按源 MAC + UDP 端口丢弃）", f.chain)
	case fwBackendNftables:
		return fmt.Sprintf("nftables（bridge %s 集合 %s，按源 MAC + UDP 端口丢弃）", f.table, f.set)
	}
	return f.backend
}

// renderCmd 替换 hook 命令中的占位符。
func renderCmd(tpl, mac, ip string, port uint16) string {
	return strings.NewReplacer(
		"{mac}", mac,
		"{ip}", ip,
		"{port}", strconv.Itoa(int(port)),
	).Replace(tpl)
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
