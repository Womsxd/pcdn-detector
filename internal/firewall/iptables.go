package firewall

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// iptables 后端的默认链（[firewall.iptables]，留空时生效）：
//   - defaultChain：端口封禁所用链（chain），默认 FORWARD；
//   - defaultInputChain：「进入路由器」所用链（input_chain），默认 INPUT——UPnP 请求的目的地通常是
//     路由器自身（设备发往路由器 IP），故默认在 INPUT 链生效；特殊网络结构（如路由器作三层转发、
//     UPnP 服务不在本机）可改为其他链（如 FORWARD）。
const (
	defaultChain      = "FORWARD"
	defaultInputChain = "INPUT"
)

// 本程序的 iptables 专用链：所有封禁规则都落在专用链里，用户配置的 chain / input_chain
// 只作为「跳转插入点」。这样启动时可以安全地整链清空，不影响用户自己的规则，也能清理掉
// 上一次进程被 SIGKILL / OOM 杀死后残留的封禁。
const (
	defaultIptablesBanChain  = "PCDN_DETECT"
	defaultIptablesUPnPChain = "PCDN_DETECT_UPNP"

	// iptables 链名上限（内核 IFNAMSIZ - 1）。
	iptablesChainMaxLen = 28
)

// resolveInputChain 返回 UPnP 拦截所用的 iptables 链（未配置时默认 INPUT）。
func resolveInputChain(chain string) string {
	if s := strings.TrimSpace(chain); s != "" {
		return s
	}
	return defaultInputChain
}

// validateIptablesChains 校验专用链名：不能与跳转链 / 彼此重名，否则启动时的整链清空
// 会误删用户自己的规则；字符集与长度还需符合 iptables 限制。
func validateIptablesChains(hook, upnpHook, ban, upnp string) error {
	for _, c := range []struct {
		field, name string
	}{
		{"ban_chain", ban},
		{"upnp_chain", upnp},
	} {
		if err := validateIptablesChainName(c.name); err != nil {
			return fmt.Errorf("[firewall.iptables] %s 无效：%w", c.field, err)
		}
	}
	if ban == hook || ban == upnpHook {
		return fmt.Errorf("[firewall.iptables] ban_chain 不能与 chain / input_chain 相同（%s）", ban)
	}
	if upnp == hook || upnp == upnpHook {
		return fmt.Errorf("[firewall.iptables] upnp_chain 不能与 chain / input_chain 相同（%s）", upnp)
	}
	if ban == upnp {
		return fmt.Errorf("[firewall.iptables] ban_chain 与 upnp_chain 不能相同（%s）", ban)
	}
	return nil
}

// validateIptablesChainName 校验单个链名：1~28 字节，只允许字母、数字、下划线与连字符。
func validateIptablesChainName(name string) error {
	if name == "" {
		return errors.New("不能为空")
	}
	if len(name) > iptablesChainMaxLen {
		return fmt.Errorf("长度不能超过 %d 个字符", iptablesChainMaxLen)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("只能包含字母、数字、下划线与连字符：%q", name)
		}
	}
	return nil
}

// ipt 执行一条 iptables / ip6tables 命令，并固定加上 -w 5 等待 xtables 锁。
// fw3 / fw4 或用户脚本可能同时操作同一把锁：不加 -w 时命令会直接以「资源暂时不可用」失败，
// 结果是封禁 / 解封静默失效（只留一行日志）。等待上限 5s 与默认命令超时一致；
// timeout 配得更短时由执行器的 context 提前终止。
func (f *Firewall) ipt(bin string, args ...string) error {
	return f.run(bin, append([]string{"-w", "5"}, args...)...)
}

// iptBins 返回本次应操作的 iptables 命令。未找到 ip6tables 时只操作 IPv4：
// 与 IPv6 相关的建立、清理、封禁、解封一律跳过（不影响 IPv4 行为，也不阻止启动）。
func (f *Firewall) iptBins() []string {
	if f.hasV6 {
		return []string{"iptables", "ip6tables"}
	}
	return []string{"iptables"}
}

// setupIptables 在启动 / reload 时对账本程序的专用链：先删跳转、清空并删除旧链，再重建并插入跳转。
// 这样上一次进程被 SIGKILL / OOM 杀死后残留的规则不会继续生效，也不会重复累积；
// 用户配置的 chain / input_chain 只作为跳转插入点，其自身规则不会被清空。
func (f *Firewall) setupIptables() {
	for _, bin := range f.iptBins() {
		f.resetIptablesChain(bin, f.chain, f.banChain)
		_ = f.ipt(bin, "-N", f.banChain)
		_ = f.ipt(bin, "-I", f.chain, "-j", f.banChain)

		if f.upnpChain == "" {
			continue
		}
		// UPnP 链无论本次是否启用都要清理（可能是上次启用时残留的）。
		f.resetIptablesChain(bin, f.upnpChain, f.upnpRuleChain)
		if f.upnp {
			_ = f.ipt(bin, "-N", f.upnpRuleChain)
			_ = f.ipt(bin, "-I", f.upnpChain, "-j", f.upnpRuleChain)
		}
	}
}

// cleanupIptables 删除跳转与专用链，清除本程序添加的全部 iptables 规则。
func (f *Firewall) cleanupIptables() {
	for _, bin := range f.iptBins() {
		f.resetIptablesChain(bin, f.chain, f.banChain)
		if f.upnpChain != "" {
			f.resetIptablesChain(bin, f.upnpChain, f.upnpRuleChain)
		}
	}
}

// resetIptablesChain 删除 hook 链上到专用链的跳转，再清空并删除专用链（对象不存在时忽略错误）。
func (f *Firewall) resetIptablesChain(bin, hook, chain string) {
	_ = f.ipt(bin, "-D", hook, "-j", chain)
	_ = f.ipt(bin, "-F", chain)
	_ = f.ipt(bin, "-X", chain)
}

// iptablesUPnP 在 iptables（v4）与 ip6tables（v6）的 UPnP 专用链上按源 MAC 拦截该设备
// 发往路由器的 UPnP 请求（黑名单模式）：UDP 与 TCP 各按目的端口（multiport）匹配后 DROP。
func (f *Firewall) iptablesUPnP(ban bool, mac string) error {
	return f.iptablesUPnPRules(ban, mac, "DROP")
}

// iptablesUPnPBlockAll 在 UPnP 专用链上拦截**全部**进入路由器的 UPnP（白名单模式）：
// 对 UDP 与 TCP 各按目的端口（multiport）插入 DROP 规则（v4/v6 各一套）。
func (f *Firewall) iptablesUPnPBlockAll(ban bool) error {
	return f.iptablesUPnPRules(ban, "", "DROP")
}

// iptablesUPnPAllow 在 UPnP 专用链上为某设备放行 UPnP（白名单模式）：
// 按源 MAC + 目的端口对 UDP 与 TCP 各插入 ACCEPT 规则（v4/v6 各一套）。
// 由于采用 -I 插入表头，后插入的 ACCEPT 会位于全量 DROP 之上而优先生效。
func (f *Firewall) iptablesUPnPAllow(ban bool, mac string) error {
	return f.iptablesUPnPRules(ban, mac, "ACCEPT")
}

// iptablesUPnPRules 在 iptables（v4）/ ip6tables（v6）的 UPnP 专用链 PCDN_DETECT_UPNP 上，
// 对 UDP 与 TCP 各插入 / 删除一条规则；跳转由 setupIptables 插在 [firewall.iptables] input_chain
// 指定的链（默认 INPUT——UPnP 请求的目的地通常是路由器自身）。
// mac 为空表示不限源 MAC（用于全量拦截）；target 为 DROP / ACCEPT。
// 封禁前先用 -C 检查，避免重复插入。
func (f *Firewall) iptablesUPnPRules(ban bool, mac, target string) error {
	chain := f.upnpRuleChain
	var firstErr error
	for _, bin := range f.iptBins() {
		for _, proto := range []string{"udp", "tcp"} {
			rule := make([]string, 0, 8)
			if mac != "" {
				rule = append(rule, "-m", "mac", "--mac-source", mac)
			}
			rule = append(rule, "-p", proto)
			if len(f.upnpPorts) > 0 {
				rule = append(rule, "-m", "multiport", "--dports", portsCSV(f.upnpPorts))
			}
			rule = append(rule, "-j", target)
			var err error
			if ban {
				check := append([]string{"-C", chain}, rule...)
				if f.ipt(bin, check...) == nil {
					continue // 规则已存在
				}
				insert := append([]string{"-I", chain}, rule...)
				err = f.ipt(bin, insert...)
			} else {
				del := append([]string{"-D", chain}, rule...)
				err = f.ipt(bin, del...)
			}
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// iptablesFullBan 在 iptables（v4）与 ip6tables（v6）的专用链上按源 MAC 对全部 UDP 流量封禁 / 解封：
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
	for _, bin := range f.iptBins() {
		for _, rule := range rules {
			if ban {
				check := append([]string{"-C", f.banChain}, rule...)
				if f.ipt(bin, check...) == nil {
					continue // 规则已存在
				}
				insert := append([]string{"-I", f.banChain}, rule...)
				if err := f.ipt(bin, insert...); err != nil && firstErr == nil {
					firstErr = err
				}
			} else {
				del := append([]string{"-D", f.banChain}, rule...)
				if err := f.ipt(bin, del...); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

// iptablesSet 在 iptables（v4）/ ip6tables（v6）的专用链上，按源 MAC + 源端口封禁/解封该触发协议。
// 封禁前先用 -C 检查，避免重复插入。
func (f *Firewall) iptablesSet(ban bool, mac string, port uint16, ip, proto string) error {
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		if family == familyV6 && !f.hasV6 {
			continue // 无 ip6tables：忽略 IPv6 封禁（包括触发报文本身来自 IPv6 的情况）
		}
		bin := "iptables"
		if family == familyV6 {
			bin = "ip6tables"
		}
		rule := []string{"-m", "mac", "--mac-source", mac, "-p", proto, "--sport", strconv.Itoa(int(port)), "-j", "DROP"}
		var err error
		if ban {
			check := append([]string{"-C", f.banChain}, rule...)
			if f.ipt(bin, check...) == nil {
				continue // 规则已存在
			}
			insert := append([]string{"-I", f.banChain}, rule...)
			err = f.ipt(bin, insert...)
		} else {
			del := append([]string{"-D", f.banChain}, rule...)
			err = f.ipt(bin, del...)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
