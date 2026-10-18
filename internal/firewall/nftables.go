package firewall

import (
	"fmt"
	"strings"
	"time"
)

// nftables 钩子：bridge 族支持的挂载点。
const (
	nftHookPrerouting  = "prerouting"
	nftHookInput       = "input"
	nftHookForward     = "forward"
	nftHookOutput      = "output"
	nftHookPostrouting = "postrouting"
)

// nftables 后端的默认对象名（[firewall.nftables]，留空时生效）：
//   - defaultNftTable：表名，默认 pcdn_detect（端口封禁链名与表名一致）；
//   - defaultNftSet：集合名前缀，默认 banned（实际使用 <set>_<family>_<proto>，如 banned_v4_udp）。
const (
	defaultNftTable = "pcdn_detect"
	defaultNftSet   = "banned"
)

// normalizeNftHook 校验并规范化 nftables 钩子名；留空时返回默认值 def
// （端口封禁链用 nftHookPrerouting，UPnP 专用链用 nftHookInput）。
func normalizeNftHook(hook, def string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(hook))
	if h == "" {
		return def, nil
	}
	switch h {
	case nftHookPrerouting, nftHookInput, nftHookForward, nftHookOutput, nftHookPostrouting:
		return h, nil
	default:
		return "", fmt.Errorf("nftables hook 无效 %q（bridge 族可选 prerouting / input / forward / output / postrouting）", hook)
	}
}

// setupNftables 初始化 bridge 族的表/链，以及按「地址族 + 协议」拆分的拼接集合与各自的丢弃规则。
// 集合为拼接（concatenation）类型，元素形如 `aa:bb:cc:dd:ee:ff . 40000`；
// 同名集合按 f.protos 与 v4/v6 展开为 <set>_<family>_<proto>（如 banned_v4_udp），
// 使 UDP 与 TCP 各自独立封禁（UDP 触发只影响 UDP 集合，TCP 触发只影响 TCP 集合）。
//
// 基础链挂到 bridge 族由 hook 指定的钩子（默认 prerouting）：prerouting 能看到所有进入网桥的帧，
// 既包含纯二层桥接转发的帧，也包含「发给路由器自身 MAC、随后被三层路由转发出去」的帧。
// PCDN 是设备↔公网的路由流量，其帧的目标 MAC 为路由器 br-lan，走的是 prerouting/input 而非
// forward，因此用 forward 钩子时规则永不命中、封禁形同虚设（改用其他钩子时启动会告警）。
// 链名固定与表名一致（nftables 中表名与链名分属不同命名空间，可同名）。
// 这些对象可能已存在，失败仅记录警告，不致命。
func (f *Firewall) setupNftables() {
	chain := f.table
	// 先删除上一次运行可能残留的同名表：进程被 SIGKILL / OOM 杀死时无法执行 Cleanup，
	// 残留的集合元素会让旧封禁继续生效；而 add table / add rule 在对象已存在时不会重建，
	// 每次启动还会重复追加 drop 规则。表不存在属于正常情况，忽略错误。
	_ = f.run("nft", fmt.Sprintf("delete table bridge %s", f.table))
	stmts := []string{
		fmt.Sprintf("add table bridge %s", f.table),
		fmt.Sprintf("add chain bridge %s %s { type filter hook %s priority -150 ; }", f.table, chain, f.hook),
	}
	// 封禁集合是否带内核超时：启用后元素到期自动消失，进程被 kill 也不会永久残留；
	// 由 Blocker 按 TTL/3 周期重新 add 续期。
	timeoutFlag := ""
	if f.banTTL > 0 {
		timeoutFlag = " flags timeout ;"
	}
	for _, family := range []string{familyV4, familyV6} {
		for _, proto := range f.protos {
			stmts = append(stmts, fmt.Sprintf("add set bridge %s %s { type ether_addr . inet_service ;%s }", f.table, f.nftSetName(family, proto), timeoutFlag))
		}
	}
	for _, proto := range f.protos {
		stmts = append(stmts,
			fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol %s ether saddr . %s sport @%s drop", f.table, chain, proto, proto, f.nftSetName(familyV4, proto)),
			fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr %s ether saddr . %s sport @%s drop", f.table, chain, proto, proto, f.nftSetName(familyV6, proto)),
		)
	}
	// 全 UDP 端口封禁：以「设备 MAC 集合 + 放行端口集合」实现，
	// 规则顺序须为「先放行白名单端口、再整体丢弃」，故 accept 规则先于 drop 规则加入。
	if f.fullBan {
		stmts = append(stmts,
			fmt.Sprintf("add set bridge %s %s { type ether_addr ;%s }", f.table, f.fullBanMacsSet(), timeoutFlag),
			fmt.Sprintf("add set bridge %s %s { type inet_service ; }", f.table, f.fullBanAllowSet()),
		)
		if len(f.fullBanAllow) > 0 {
			stmts = append(stmts,
				fmt.Sprintf("add element bridge %s %s { %s }", f.table, f.fullBanAllowSet(), portsCSV(f.fullBanAllow)),
			)
		}
		stmts = append(stmts,
			fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol udp ether saddr @%s udp dport @%s accept", f.table, chain, f.fullBanMacsSet(), f.fullBanAllowSet()),
			fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol udp ether saddr @%s drop", f.table, chain, f.fullBanMacsSet()),
			fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr udp ether saddr @%s udp dport @%s accept", f.table, chain, f.fullBanMacsSet(), f.fullBanAllowSet()),
			fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr udp ether saddr @%s drop", f.table, chain, f.fullBanMacsSet()),
		)
	}
	// UPnP 拦截：使用**独立的** bridge 基础链（钩子由 [firewall.nftables] input_hook 决定，
	// 默认 input，即「进入路由器」方向），按目的端口（UDP/TCP）处理设备发往路由器的 UPnP 请求；
	// 无目的端口过滤时（upnpPorts 为空）作用于该方向全部 UDP/TCP。
	//   - 黑名单模式（upnpBlockAll=false）：「设备 MAC 集合」命中即丢弃；
	//   - 白名单模式（upnpBlockAll=true）：先放行「放行名单集合」命中者，其余一律丢弃。
	if f.upnp {
		upChain := f.upnpChainName()
		stmts = append(stmts, fmt.Sprintf("add chain bridge %s %s { type filter hook %s priority -150 ; }", f.table, upChain, f.upnpInputHook))
		dp := ""
		if len(f.upnpPorts) > 0 {
			dp = portsCSV(f.upnpPorts)
		}
		dport := func(proto string) string {
			if dp == "" {
				return ""
			}
			return fmt.Sprintf(" %s dport { %s }", proto, dp)
		}
		if f.upnpBlockAll {
			stmts = append(stmts, fmt.Sprintf("add set bridge %s %s { type ether_addr ; }", f.table, f.upnpAllowSet()))
			for _, proto := range []string{"udp", "tcp"} {
				stmts = append(stmts,
					fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol %s ether saddr @%s%s accept", f.table, upChain, proto, f.upnpAllowSet(), dport(proto)),
					fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol %s%s drop", f.table, upChain, proto, dport(proto)),
					fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr %s ether saddr @%s%s accept", f.table, upChain, proto, f.upnpAllowSet(), dport(proto)),
					fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr %s%s drop", f.table, upChain, proto, dport(proto)),
				)
			}
		} else {
			stmts = append(stmts, fmt.Sprintf("add set bridge %s %s { type ether_addr ; }", f.table, f.upnpMacsSet()))
			for _, proto := range []string{"udp", "tcp"} {
				stmts = append(stmts,
					fmt.Sprintf("add rule bridge %s %s ether type ip ip protocol %s ether saddr @%s%s drop", f.table, upChain, proto, f.upnpMacsSet(), dport(proto)),
					fmt.Sprintf("add rule bridge %s %s ether type ip6 ip6 nexthdr %s ether saddr @%s%s drop", f.table, upChain, proto, f.upnpMacsSet(), dport(proto)),
				)
			}
		}
	}
	for _, s := range stmts {
		if err := f.run("nft", s); err != nil {
			f.logger.Printf("警告：nft 初始化语句失败（可能已存在）：%v", err)
		}
	}
}

// fullBanMacsSet / fullBanAllowSet 返回 nftables 中全端口封禁所用的集合名
// （分别为「被全封禁的设备 MAC 集合」与「仍放行的 UDP 端口集合」）。
func (f *Firewall) fullBanMacsSet() string  { return f.set + "_fullban_macs" }
func (f *Firewall) fullBanAllowSet() string { return f.set + "_fullban_allow" }

// upnpMacsSet 返回 nftables 中 UPnP 拦截所用的「被拦截设备 MAC 集合」名（黑名单模式）。
func (f *Firewall) upnpMacsSet() string { return f.set + "_upnp_macs" }

// upnpAllowSet 返回 nftables 中 UPnP 白名单模式所用的「放行设备 MAC 集合」名。
func (f *Firewall) upnpAllowSet() string { return f.set + "_upnp_allow" }

// upnpChainName 返回 nftables 中 UPnP 拦截所用的独立基础链名（与端口封禁链分开，可各挂不同钩子）。
func (f *Firewall) upnpChainName() string { return f.table + "_upnp" }

// nftUPnP 在 nftables 的「被 UPnP 拦截设备 MAC 集合」中添加 / 删除元素（bridge 族）。
func (f *Firewall) nftUPnP(ban bool, mac string) error {
	return f.nftUPnPElement(ban, f.upnpMacsSet(), mac)
}

// nftUPnPAllow 在 nftables 的「UPnP 放行设备 MAC 集合」中添加 / 删除元素（bridge 族）。
func (f *Firewall) nftUPnPAllow(ban bool, mac string) error {
	return f.nftUPnPElement(ban, f.upnpAllowSet(), mac)
}

// nftUPnPElement 在指定 MAC 集合中添加 / 删除元素。
func (f *Firewall) nftUPnPElement(ban bool, set, mac string) error {
	verb := "add"
	if !ban {
		verb = "delete"
	}
	return f.run("nft", fmt.Sprintf("%s element bridge %s %s { %s }", verb, f.table, set, mac))
}

// nftFullBan 在 nftables 的「被全封禁设备 MAC 集合」中添加 / 删除元素（bridge 族）。
func (f *Firewall) nftFullBan(ban bool, mac string) error {
	verb := "add"
	if !ban {
		verb = "delete"
	}
	suffix := ""
	if ban {
		suffix = f.nftTimeoutSuffix()
	}
	cmd := fmt.Sprintf("%s element bridge %s %s { %s%s }", verb, f.table, f.fullBanMacsSet(), mac, suffix)
	return f.run("nft", cmd)
}

// nftTimeoutSuffix 返回 add element 时附加的内核超时（秒）；未启用超时时返回空串。
func (f *Firewall) nftTimeoutSuffix() string {
	if f.banTTL <= 0 {
		return ""
	}
	return fmt.Sprintf(" timeout %ds", int64(f.banTTL/time.Second))
}

// nftSetName 返回「地址族 + 协议」对应的 nftables 集合名（如 banned_v4_udp / banned_v6_tcp）。
func (f *Firewall) nftSetName(family, proto string) string {
	return f.set + "_" + family + "_" + proto
}

// nftSet 在「地址族 + 协议」对应的 nftables 集合中按「MAC . 端口」添加 / 删除元素。
func (f *Firewall) nftSet(ban bool, mac string, port uint16, ip, proto string) error {
	verb := "add"
	if !ban {
		verb = "delete"
	}
	suffix := ""
	if ban {
		suffix = f.nftTimeoutSuffix()
	}
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		cmd := fmt.Sprintf("%s element bridge %s %s { %s . %d%s }", verb, f.table, f.nftSetName(family, proto), mac, port, suffix)
		if err := f.run("nft", cmd); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
