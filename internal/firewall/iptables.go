package firewall

import "strconv"

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
