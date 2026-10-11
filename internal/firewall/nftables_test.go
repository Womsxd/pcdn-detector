package firewall

import (
	"testing"

	"pcdn-detect/internal/config"
)

// nftables 后端：初始化按「地址族 + 协议」拆分的拼接集合与各自规则；protocol=udp 时只有 UDP。
func TestFirewallNftables(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if rec.countContains("add chain bridge pcdn_detect pcdn_detect { type filter hook prerouting priority -150 ; }") != 1 {
		t.Fatalf("基础链应挂到 prerouting 钩子（能看到路由转发的帧），got %v", rec.snapshot())
	}
	if rec.countContains("add set bridge pcdn_detect banned_v4_udp { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化 v4 UDP 拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add set bridge pcdn_detect banned_v6_udp { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化 v6 UDP 拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect pcdn_detect ether type ip ip protocol udp ether saddr . udp sport @banned_v4_udp drop") != 1 {
		t.Fatalf("应初始化 IPv4 UDP 规则，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect pcdn_detect ether type ip6 ip6 nexthdr udp ether saddr . udp sport @banned_v6_udp drop") != 1 {
		t.Fatalf("应初始化 IPv6 UDP 规则，got %v", rec.snapshot())
	}
	if n := rec.countContains("tcp"); n != 0 {
		t.Fatalf("protocol=udp 不应初始化 TCP 对象，got %v", rec.snapshot())
	}

	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if rec.countContains("nft add element bridge pcdn_detect banned_v4_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 ||
		rec.countContains("nft add element bridge pcdn_detect banned_v6_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("默认应同时封禁 v4/v6，命令不符：%v", rec.snapshot())
	}
	if rec.countContains("nft delete element bridge pcdn_detect banned_v4_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 ||
		rec.countContains("nft delete element bridge pcdn_detect banned_v6_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("默认应同时解封 v4/v6，命令不符：%v", rec.snapshot())
	}
}

// nftables 钩子可由 [firewall] hook 指定；链名始终与表名一致（自定义表名时亦然）。
func TestFirewallNftablesCustomHook(t *testing.T) {
	rec := &cmdRecorder{}
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables", Nftables: config.FirewallNftablesConfig{Table: "mytable", Hook: "input"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run); err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if rec.countContains("add table bridge mytable") != 1 {
		t.Fatalf("应使用自定义表名，got %v", rec.snapshot())
	}
	if rec.countContains("add chain bridge mytable mytable { type filter hook input priority -150 ; }") != 1 {
		t.Fatalf("链名应等于表名、钩子应为 input，got %v", rec.snapshot())
	}
}

// 非法 nftables 钩子应报错退出。
func TestFirewallNftablesInvalidHook(t *testing.T) {
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables", Nftables: config.FirewallNftablesConfig{Hook: "preroutingX"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("非法 hook 应报错")
	}
}

// ban_both=false：v4 触发时元素只加入 banned_v4_udp。
func TestFirewallNftablesSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables", BanBoth: boolPtr(false)}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if rec.countContains("nft add element bridge pcdn_detect banned_v4_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("v4 触发应加入 banned_v4_udp，got %v", rec.snapshot())
	}
	if n := rec.countContains("banned_v6_udp { aa:bb:cc"); n != 0 {
		t.Fatalf("v4 触发不应加入 banned_v6_udp，got %v", rec.snapshot())
	}
}

// protocol=all：nftables 为 UDP 与 TCP 各自初始化独立集合与丢弃规则。
func TestFirewallNftablesUDPAndTCP(t *testing.T) {
	rec := &cmdRecorder{}
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeAll, testLogger(), rec.run); err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	for _, want := range []string{
		"add set bridge pcdn_detect banned_v4_udp { type ether_addr . inet_service ; }",
		"add set bridge pcdn_detect banned_v4_tcp { type ether_addr . inet_service ; }",
		"add set bridge pcdn_detect banned_v6_udp { type ether_addr . inet_service ; }",
		"add set bridge pcdn_detect banned_v6_tcp { type ether_addr . inet_service ; }",
		"add rule bridge pcdn_detect pcdn_detect ether type ip ip protocol udp ether saddr . udp sport @banned_v4_udp drop",
		"add rule bridge pcdn_detect pcdn_detect ether type ip ip protocol tcp ether saddr . tcp sport @banned_v4_tcp drop",
		"add rule bridge pcdn_detect pcdn_detect ether type ip6 ip6 nexthdr udp ether saddr . udp sport @banned_v6_udp drop",
		"add rule bridge pcdn_detect pcdn_detect ether type ip6 ip6 nexthdr tcp ether saddr . tcp sport @banned_v6_tcp drop",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("应初始化 %q，got %d：%v", want, n, rec.snapshot())
		}
	}
}

// 封禁协议随触发协议：UDP 触发只加入 UDP 集合，不触碰 TCP 集合。
func TestFirewallNftablesPerProtocol(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeAll, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if rec.countContains("nft add element bridge pcdn_detect banned_v4_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 ||
		rec.countContains("nft add element bridge pcdn_detect banned_v6_udp { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("UDP 触发应加入 UDP 集合，got %v", rec.snapshot())
	}
	if n := rec.countContains("banned_v4_tcp { aa:bb:cc"); n != 0 {
		t.Fatalf("UDP 触发不应加入 TCP 集合，got %v", rec.snapshot())
	}
}

// 全端口封禁（nftables）：初始化 MAC 集合与放行端口集合，并加入 accept / drop 规则；
// 封禁 / 解封即在该 MAC 集合中添加 / 删除元素。
func TestFirewallNftablesFullBan(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{Mode: "on"}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	for _, want := range []string{
		"add set bridge pcdn_detect banned_fullban_macs { type ether_addr ; }",
		"add set bridge pcdn_detect banned_fullban_allow { type inet_service ; }",
		"add element bridge pcdn_detect banned_fullban_allow { 53,67,68,123,546,547 }",
		"add rule bridge pcdn_detect pcdn_detect ether type ip ip protocol udp ether saddr @banned_fullban_macs udp dport @banned_fullban_allow accept",
		"add rule bridge pcdn_detect pcdn_detect ether type ip ip protocol udp ether saddr @banned_fullban_macs drop",
		"add rule bridge pcdn_detect pcdn_detect ether type ip6 ip6 nexthdr udp ether saddr @banned_fullban_macs udp dport @banned_fullban_allow accept",
		"add rule bridge pcdn_detect pcdn_detect ether type ip6 ip6 nexthdr udp ether saddr @banned_fullban_macs drop",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("应初始化 %q，got %d：%v", want, n, rec.snapshot())
		}
	}

	if err := f.FullBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("全端口封禁失败：%v", err)
	}
	if err := f.FullUnban("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("全端口解封失败：%v", err)
	}
	if n := rec.countContains("nft add element bridge pcdn_detect banned_fullban_macs { aa:bb:cc:dd:ee:ff }"); n != 1 {
		t.Fatalf("全端口封禁应加入 MAC 集合，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("nft delete element bridge pcdn_detect banned_fullban_macs { aa:bb:cc:dd:ee:ff }"); n != 1 {
		t.Fatalf("全端口解封应删除 MAC 集合元素，got %d：%v", n, rec.snapshot())
	}
}

// 关闭 full_ban 时不应初始化任何全端口封禁对象。
func TestFirewallNftablesFullBanOff(t *testing.T) {
	rec := &cmdRecorder{}
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run); err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if n := rec.countContains("fullban"); n != 0 {
		t.Fatalf("未启用 full_ban 时不应初始化相关对象，got %v", rec.snapshot())
	}
}

// UPnP 拦截（nftables）：使用独立的 bridge 基础链（默认钩子 input）初始化 MAC 集合与
// 按目的端口（UDP/TCP，v4/v6）丢弃的规则；拦截 / 解除即在该 MAC 集合中添加 / 删除元素。
func TestFirewallNftablesUPnP(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{},
		config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	for _, want := range []string{
		"add chain bridge pcdn_detect pcdn_detect_upnp { type filter hook input priority -150 ; }",
		"add set bridge pcdn_detect banned_upnp_macs { type ether_addr ; }",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip ip protocol udp ether saddr @banned_upnp_macs udp dport { 1900,5000 } drop",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip ip protocol tcp ether saddr @banned_upnp_macs tcp dport { 1900,5000 } drop",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip6 ip6 nexthdr udp ether saddr @banned_upnp_macs udp dport { 1900,5000 } drop",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip6 ip6 nexthdr tcp ether saddr @banned_upnp_macs tcp dport { 1900,5000 } drop",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("应初始化 %q，got %d：%v", want, n, rec.snapshot())
		}
	}

	if err := f.UPnPBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 拦截失败：%v", err)
	}
	if err := f.UPnPUnban("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 解除失败：%v", err)
	}
	if n := rec.countContains("nft add element bridge pcdn_detect banned_upnp_macs { aa:bb:cc:dd:ee:ff }"); n != 1 {
		t.Fatalf("UPnP 拦截应加入 MAC 集合，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("nft delete element bridge pcdn_detect banned_upnp_macs { aa:bb:cc:dd:ee:ff }"); n != 1 {
		t.Fatalf("UPnP 解除应删除 MAC 集合元素，got %d：%v", n, rec.snapshot())
	}
}

// UPnP 拦截（nftables，白名单模式）：先放行「放行名单集合」命中者，再对其余一律丢弃；
// 放行 / 取消放行即在放行集合中添加 / 删除元素。
func TestFirewallNftablesUPnPBlockAll(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{},
		config.UPnPConfig{Mode: "on"}, config.UPnPFilter{BlockAll: true}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	for _, want := range []string{
		"add set bridge pcdn_detect banned_upnp_allow { type ether_addr ; }",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip ip protocol udp ether saddr @banned_upnp_allow udp dport { 1900,5000 } accept",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip ip protocol udp udp dport { 1900,5000 } drop",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip6 ip6 nexthdr tcp ether saddr @banned_upnp_allow tcp dport { 1900,5000 } accept",
		"add rule bridge pcdn_detect pcdn_detect_upnp ether type ip6 ip6 nexthdr tcp tcp dport { 1900,5000 } drop",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("应初始化 %q，got %d：%v", want, n, rec.snapshot())
		}
	}
	// 白名单模式下不应创建「被拦截设备」集合。
	if n := rec.countContains("banned_upnp_macs"); n != 0 {
		t.Fatalf("白名单模式不应创建被拦截设备集合，got %v", rec.snapshot())
	}

	if err := f.UPnPAllow("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("放行失败：%v", err)
	}
	if err := f.UPnPDisallow("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("取消放行失败：%v", err)
	}
	if n := rec.countContains("nft add element bridge pcdn_detect banned_upnp_allow { aa:bb:cc:dd:ee:ff }"); n != 1 {
		t.Fatalf("放行应加入放行集合，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("nft delete element bridge pcdn_detect banned_upnp_allow { aa:bb:cc:dd:ee:ff }"); n != 1 {
		t.Fatalf("取消放行应删除放行集合元素，got %d：%v", n, rec.snapshot())
	}
}

// 关闭 upnp 时不应初始化任何 UPnP 拦截对象。
func TestFirewallNftablesUPnPOff(t *testing.T) {
	rec := &cmdRecorder{}
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run); err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if n := rec.countContains("upnp"); n != 0 {
		t.Fatalf("未启用 upnp 时不应初始化相关对象，got %v", rec.snapshot())
	}
}

// UPnP 拦截（nftables）：[firewall.nftables] input_hook 可配置 UPnP 专用链的钩子（默认 input）。
func TestFirewallNftablesUPnPCustomInputHook(t *testing.T) {
	rec := &cmdRecorder{}
	if _, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend:  "nftables",
		Nftables: config.FirewallNftablesConfig{InputHook: "prerouting"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), rec.run); err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if n := rec.countContains("add chain bridge pcdn_detect pcdn_detect_upnp { type filter hook prerouting priority -150 ; }"); n != 1 {
		t.Fatalf("input_hook=prerouting 时 UPnP 专用链应挂到 prerouting，got %v", rec.snapshot())
	}
	// 非法 input_hook 应报错。
	if _, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend:  "nftables",
		Nftables: config.FirewallNftablesConfig{InputHook: "preroutingX"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("非法 input_hook 应报错")
	}
}
