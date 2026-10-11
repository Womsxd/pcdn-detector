package firewall

import (
	"strings"
	"testing"

	"pcdn-detect/internal/config"
)

// iptables 后端：默认同时封禁，按源 MAC + UDP 源端口分别对 iptables/ip6tables 操作。
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
	if n := rec.countContains("-I FORWARD " + rule); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 插入规则，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-D FORWARD " + rule); n != 2 {
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
	if n := rec.countContains("-I FORWARD " + rule); n != 1 {
		t.Fatalf("v4 触发应只操作 iptables，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("ip6tables"); n != 0 {
		t.Fatalf("不应触碰 ip6tables，got %v", rec.snapshot())
	}
}

// 规则已存在时应跳过插入（-C 成功）。
func TestFirewallIptablesIdempotent(t *testing.T) {
	rec := &cmdRecorder{} // -C 返回成功，表示规则已存在
	f, _ := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if n := rec.countContains("-I FORWARD"); n != 0 {
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
	if n := udpRec.countContains("-I FORWARD " + udpRule); n != 2 {
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
	if n := tcpRec.countContains("-I FORWARD " + tcpRule); n != 2 {
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
	if err := f.FullBan("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("全端口封禁失败：%v", err)
	}
	if err := f.FullUnban("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("全端口解封失败：%v", err)
	}

	drop := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -j DROP"
	accept := "-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 53,67,68,123,546,547 -j ACCEPT"
	if n := rec.countContains("-I FORWARD " + drop); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 插入 DROP，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-I FORWARD " + accept); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 插入 ACCEPT，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("-D FORWARD " + drop); n != 2 {
		t.Fatalf("应分别对 iptables/ip6tables 删除 DROP，got %d：%v", n, rec.snapshot())
	}

	// 第一条插入应为 DROP（ACCEPT 在其后插入，从而位于其上方）。
	calls := rec.snapshot()
	if len(calls) == 0 || !strings.Contains(calls[0], "DROP") {
		t.Fatalf("应先插入 DROP 规则，got %v", calls)
	}
}
