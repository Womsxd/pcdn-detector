package firewall

import (
	"strings"
	"testing"

	"pcdn-detect/internal/config"
)

// iptables 后端：默认同时封禁，按源 MAC + UDP 源端口分别对 iptables/ip6tables 的专用链操作。
func TestFirewallIptables(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}

	rule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp --sport 40000 -j DROP"
	if n := rec.countContains("-I PCDN_DETECT " + rule); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 插入规则，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-D PCDN_DETECT " + rule); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 删除规则，got %d 次：%v", n, rec.snapshot())
	}
}

// ban_both=false：v4 触发时仅操作 iptables，不触碰 ip6tables。
func TestFirewallIptablesSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables", BanBoth: boolPtr(false)}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}

	rule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp --sport 40000 -j DROP"
	if n := rec.countContains("iptables -I PCDN_DETECT " + rule); n != 1 {
		t.Fatalf("v4 触发应只操作 iptables，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("ip6tables -I PCDN_DETECT " + rule); n != 0 {
		t.Fatalf("不应向 ip6tables 插入封禁规则，got %d 次：%v", n, rec.snapshot())
	}
}

// 规则已存在时应跳过插入（-C 成功）。
func TestFirewallIptablesIdempotent(t *testing.T) {
	rec := &cmdRecorder{} // -C 返回成功，表示规则已存在
	f, _ := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if n := rec.countContains("-I PCDN_DETECT -m mac"); n != 0 {
		t.Fatalf("规则已存在时不应重复插入，got %v", rec.snapshot())
	}
}

// 封禁协议随触发协议：iptables 下 Ban("udp") 只封 UDP、Ban("tcp") 只封 TCP（各自对 v4/v6 生效）。
func TestFirewallIptablesPerProtocol(t *testing.T) {
	udpRec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeAll, testLogger(), udpRec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	udpRule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp --sport 40000 -j DROP"
	if n := udpRec.countContains("-I PCDN_DETECT " + udpRule); n != 2 {
		t.Fatalf("UDP 触发应插入 UDP 规则（v4/v6 各一），got %d：%v", n, udpRec.snapshot())
	}
	if n := udpRec.countContains("-p tcp"); n != 0 {
		t.Fatalf("UDP 触发不应封禁 TCP，got %d：%v", n, udpRec.snapshot())
	}

	tcpRec := &cmdRecorder{failCheck: true}
	f2, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeAll, testLogger(), tcpRec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f2.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "tcp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	tcpRule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p tcp --sport 40000 -j DROP"
	if n := tcpRec.countContains("-I PCDN_DETECT " + tcpRule); n != 2 {
		t.Fatalf("TCP 触发应插入 TCP 规则（v4/v6 各一），got %d：%v", n, tcpRec.snapshot())
	}
	if n := tcpRec.countContains("-p udp"); n != 0 {
		t.Fatalf("TCP 触发不应封禁 UDP，got %d：%v", n, tcpRec.snapshot())
	}
}

// 全端口封禁（iptables）：对 v4/v6 各插入 DROP 与 ACCEPT，且 DROP 先于 ACCEPT 插入
// （使 ACCEPT 位于 DROP 之上，白名单端口优先生效）；解封时两条规则都删除。
func TestFirewallIptablesFullBan(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{Mode: "on"}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if !f.FullBanEnabled() {
		t.Fatalf("[full_ban] mode=on 时应启用全端口封禁")
	}
	if err := f.FullBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("全端口封禁失败：%v", err)
	}
	if err := f.FullUnban("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("全端口解封失败：%v", err)
	}

	drop := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -j DROP"
	accept := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 53,67,68,123,546,547 -j ACCEPT"
	if n := rec.countContains("-I PCDN_DETECT " + drop); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 插入 DROP，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-I PCDN_DETECT " + accept); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 插入 ACCEPT，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-D PCDN_DETECT " + drop); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 删除 DROP，got %d：%v", n, rec.snapshot())
	}

	// 第一条写入专用链的规则应为 DROP（ACCEPT 在其后插入，从而位于其上方）。
	for _, c := range rec.snapshot() {
		if strings.Contains(c, "-I PCDN_DETECT ") {
			if !strings.Contains(c, "DROP") {
				t.Fatalf("应先插入 DROP 规则，got %v", rec.snapshot())
			}
			break
		}
	}
}

// UPnP 拦截（iptables）：规则写入专用链 UPnP 链，跳转插在 INPUT（非 FORWARD），
// 对 iptables/ip6tables 各下发；解封时删除。
func TestFirewallIptablesUPnP(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{},
		config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.UPnPBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 拦截失败：%v", err)
	}
	if err := f.UPnPUnban("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 解除失败：%v", err)
	}

	udpRule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 1900,5000 -j DROP"
	tcpRule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p tcp -m multiport --dports 1900,5000 -j DROP"
	for _, rule := range []string{udpRule, tcpRule} {
		if n := rec.countContains("-I PCDN_DETECT_UPNP " + rule); n != 2 {
			t.Fatalf("应分别对 iptables/ip6tables 在 UPnP 专用链插入 %q，got %d：%v", rule, n, rec.snapshot())
		}
		if n := rec.countContains("-D PCDN_DETECT_UPNP " + rule); n != 2 {
			t.Fatalf("应分别对 iptables/ip6tables 删除 %q，got %d：%v", rule, n, rec.snapshot())
		}
	}
	if n := rec.countContains("-I FORWARD -m mac"); n != 0 {
		t.Fatalf("UPnP 拦截规则不应直接插入 FORWARD，got %v", rec.snapshot())
	}
	if !rec.has("iptables -I INPUT -j PCDN_DETECT_UPNP") {
		t.Fatalf("应在 INPUT 插入到 UPnP 专用链的跳转，got %v", rec.snapshot())
	}
}

// UPnP 拦截（iptables）：[firewall.iptables] input_chain 可配置跳转插入点（默认 INPUT）。
func TestFirewallIptablesUPnPCustomChain(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend:  "iptables",
		Iptables: config.FirewallIptablesConfig{InputChain: "FORWARD"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.UPnPBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 拦截失败：%v", err)
	}
	rule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 1900,5000 -j DROP"
	if n := rec.countContains("-I PCDN_DETECT_UPNP " + rule); n != 2 {
		t.Fatalf("规则应写入 UPnP 专用链（v4/v6 各一），got %d：%v", n, rec.snapshot())
	}
	if !rec.has("iptables -I FORWARD -j PCDN_DETECT_UPNP") || !rec.has("ip6tables -I FORWARD -j PCDN_DETECT_UPNP") {
		t.Fatalf("input_chain=FORWARD 时应在 FORWARD 插入跳转，got %v", rec.snapshot())
	}
	if n := rec.countContains("-I INPUT "); n != 0 {
		t.Fatalf("自定义 input_chain 后不应再使用 INPUT，got %v", rec.snapshot())
	}
}

// UPnP 拦截（iptables，白名单模式）：先拦截全部（无源 MAC 的 DROP），再为名单设备插入 ACCEPT 放行。
func TestFirewallIptablesUPnPBlockAll(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{},
		config.UPnPConfig{Mode: "on"}, config.UPnPFilter{BlockAll: true, Devices: []string{"aa:bb:cc:dd:ee:ff"}},
		config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.UPnPBlockAll(); err != nil {
		t.Fatalf("全量拦截失败：%v", err)
	}
	if err := f.UPnPAllow("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("放行失败：%v", err)
	}
	if err := f.UPnPDisallow("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("取消放行失败：%v", err)
	}
	if err := f.UPnPUnblockAll(); err != nil {
		t.Fatalf("解除全量拦截失败：%v", err)
	}

	drop := "-p udp -m multiport --dports 1900,5000 -j DROP"
	if n := rec.countContains("-I PCDN_DETECT_UPNP " + drop); n != 2 {
		t.Fatalf("全量拦截应对 v4/v6 各插入一条 DROP（无源 MAC），got %d：%v", n, rec.snapshot())
	}
	allow := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 1900,5000 -j ACCEPT"
	if n := rec.countContains("-I PCDN_DETECT_UPNP " + allow); n != 2 {
		t.Fatalf("放行应对 v4/v6 各插入一条 ACCEPT，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-D PCDN_DETECT_UPNP " + drop); n != 2 {
		t.Fatalf("解除全量拦截应删除 DROP 规则，got %d", n)
	}
	if n := rec.countContains("-D PCDN_DETECT_UPNP " + allow); n != 2 {
		t.Fatalf("取消放行应删除 ACCEPT 规则，got %d", n)
	}
}

// 专用链名可自定义：规则与跳转都使用配置的名称。
func TestFirewallIptablesCustomChainNames(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "iptables",
		Iptables: config.FirewallIptablesConfig{BanChain: "MY_BAN", UPnPChain: "MY_UPNP"},
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if !rec.has("iptables -I FORWARD -j MY_BAN") || !rec.has("ip6tables -I FORWARD -j MY_BAN") {
		t.Fatalf("应在跳转链插入到自定义专用链的跳转，got %v", rec.snapshot())
	}
	rule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp --sport 40000 -j DROP"
	if n := rec.countContains("-I MY_BAN " + rule); n != 2 {
		t.Fatalf("规则应写入自定义专用链，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-D MY_BAN " + rule); n != 2 {
		t.Fatalf("应从自定义专用链删除规则，got %d：%v", n, rec.snapshot())
	}

	// UPnP 专用链名同样可自定义。
	upRec := &cmdRecorder{failCheck: true}
	upFw, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend:  "iptables",
		Iptables: config.FirewallIptablesConfig{UPnPChain: "MY_UPNP"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), upRec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := upFw.UPnPBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 拦截失败：%v", err)
	}
	if !upRec.has("iptables -I INPUT -j MY_UPNP") {
		t.Fatalf("应在 INPUT 插入到自定义 UPnP 专用链的跳转，got %v", upRec.snapshot())
	}
	upRule := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 1900,5000 -j DROP"
	if n := upRec.countContains("-I MY_UPNP " + upRule); n != 2 {
		t.Fatalf("UPnP 规则应写入自定义专用链，got %d：%v", n, upRec.snapshot())
	}
}

// 专用链名与跳转链重名 / 含非法字符 / 超长时应拒绝构建（否则启动清空会误删用户规则）。
func TestFirewallIptablesInvalidChainNames(t *testing.T) {
	cases := []config.FirewallIptablesConfig{
		{BanChain: "FORWARD"},
		{UPnPChain: "INPUT"},
		{BanChain: "PCDN DETECT"},
		{BanChain: strings.Repeat("A", iptablesChainMaxLen+1)},
		{BanChain: "SAME", UPnPChain: "SAME"},
	}
	for _, c := range cases {
		if _, err := newFirewall(config.FirewallConfig{Backend: "iptables", Iptables: c}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
			t.Fatalf("应拒绝非法专用链名：%+v", c)
		}
	}
}

// 启动时对账专用链：清空并重建后插入跳转；Cleanup 删除跳转与专用链。
// 这样被 SIGKILL / OOM 杀死后残留的封禁不会继续生效。
func TestFirewallIptablesSetupReconcilesChains(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	for _, want := range []string{
		"iptables -D FORWARD -j PCDN_DETECT",
		"iptables -F PCDN_DETECT",
		"iptables -X PCDN_DETECT",
		"iptables -N PCDN_DETECT",
		"iptables -I FORWARD -j PCDN_DETECT",
		"ip6tables -F PCDN_DETECT",
		"ip6tables -X PCDN_DETECT",
		"ip6tables -I FORWARD -j PCDN_DETECT",
		// 上次运行若启用过 UPnP，其专用链同样需要清理。
		"iptables -F PCDN_DETECT_UPNP",
		"ip6tables -X PCDN_DETECT_UPNP",
	} {
		if !rec.has(want) {
			t.Fatalf("应执行 %q，got %v", want, rec.snapshot())
		}
	}

	f.Cleanup()
	for _, want := range []string{
		"iptables -D FORWARD -j PCDN_DETECT",
		"iptables -F PCDN_DETECT",
		"iptables -X PCDN_DETECT",
		"ip6tables -F PCDN_DETECT",
		"ip6tables -X PCDN_DETECT",
	} {
		if !rec.has(want) {
			t.Fatalf("Cleanup 应执行 %q，got %v", want, rec.snapshot())
		}
	}
}
