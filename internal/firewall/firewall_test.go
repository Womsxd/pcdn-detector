package firewall

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"pcdn-detect/internal/config"
)

// cmdRecorder 记录被执行的命令，并可让 -C（检查规则）返回失败以模拟规则不存在。
type cmdRecorder struct {
	mu        sync.Mutex
	calls     []string
	failCheck bool
}

func (r *cmdRecorder) run(name string, args ...string) error {
	r.mu.Lock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.mu.Unlock()
	if r.failCheck {
		for _, a := range args {
			if a == "-C" {
				return fmt.Errorf("(fake) rule absent")
			}
		}
	}
	return nil
}

func (r *cmdRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *cmdRecorder) countContains(sub string) int {
	n := 0
	for _, c := range r.snapshot() {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func boolPtr(v bool) *bool { return &v }

// 默认 ban_both=true：hook 命令对 v4/v6 各执行一次，可用 {family} 区分。
func TestFirewallHook(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {ip} {port} {family}",
		UnbanCmd: "unban {mac} {ip} {port} {family}",
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

	got := rec.snapshot()
	want := []string{
		"sh -c ban aa:bb:cc:dd:ee:ff 192.168.1.5 40000 v4",
		"sh -c ban aa:bb:cc:dd:ee:ff 192.168.1.5 40000 v6",
		"sh -c unban aa:bb:cc:dd:ee:ff 192.168.1.5 40000 v4",
		"sh -c unban aa:bb:cc:dd:ee:ff 192.168.1.5 40000 v6",
	}
	if len(got) != len(want) {
		t.Fatalf("命令数量不符：got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条命令不符：got %q want %q", i, got[i], want[i])
		}
	}
}

// ban_both=false：hook 仅对触发到的地址族执行一次（v4 地址 -> 只发 v4）。
func TestFirewallHookSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {family}",
		UnbanCmd: "unban {mac} {port} {family}",
		BanBoth:  boolPtr(false),
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}

	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "2408::1", 40000, "udp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}

	if n := rec.countContains("sh -c ban aa:bb:cc:dd:ee:ff 40000 v4"); n != 1 {
		t.Fatalf("v4 地址应只封禁 v4，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c ban aa:bb:cc:dd:ee:ff 40000 v6"); n != 1 {
		t.Fatalf("v6 地址应只封禁 v6，got %d 次：%v", n, rec.snapshot())
	}
}

func TestFirewallHookRequiresCommands(t *testing.T) {
	if _, err := newFirewall(config.FirewallConfig{Backend: "hook"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("hook 后端缺少命令应报错")
	}
}

func TestFirewallUnknownBackend(t *testing.T) {
	if _, err := newFirewall(config.FirewallConfig{Backend: "iptables2"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("未知后端应报错")
	}
}

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
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables", Table: "mytable", Hook: "input"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run); err != nil {
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
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables", Hook: "preroutingX"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
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

// 退出时（Cleanup）应删除整张 nftables 表，连带链、集合与规则一并清除。
func TestFirewallCleanupNftables(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	f.Cleanup()
	if n := rec.countContains("nft delete table bridge pcdn_detect"); n != 1 {
		t.Fatalf("退出时应删除 nftables 表，got %d 次：%v", n, rec.snapshot())
	}
}

// 非 nftables 后端不应在退出时执行删除表的破坏性操作。
func TestFirewallCleanupOtherBackends(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	f.Cleanup()
	if n := rec.countContains("delete table"); n != 0 {
		t.Fatalf("iptables 后端不应删除表，got %v", rec.snapshot())
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

// 全端口封禁（hook）：[full_ban] 的 ban_cmd / unban_cmd 支持 {mac} 与 {ports} 占位符，仅执行一次。
func TestFirewallHookFullBan(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port}",
		UnbanCmd: "unban {mac} {port}",
	}, config.FullBanConfig{
		Mode:     "on",
		BanCmd:   "fullban {mac} {ports}",
		UnbanCmd: "fullunban {mac}",
	}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.FullBan("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("全端口封禁失败：%v", err)
	}
	if err := f.FullUnban("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("全端口解封失败：%v", err)
	}
	for _, want := range []string{
		"sh -c fullban aa:bb:cc:dd:ee:ff 53,67,68,123,546,547",
		"sh -c fullunban aa:bb:cc:dd:ee:ff",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("命令 %q 应执行一次，got %d：%v", want, n, rec.snapshot())
		}
	}
}

// hook 后端启用 full_ban 时必须配置 [full_ban] 的 ban_cmd / unban_cmd。
func TestFirewallHookFullBanRequiresCommands(t *testing.T) {
	_, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port}",
		UnbanCmd: "unban {mac} {port}",
	}, config.FullBanConfig{Mode: "on"}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err == nil {
		t.Fatalf("hook 后端启用 full_ban 但缺少命令应报错")
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

	if err := f.FullBan("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("全端口封禁失败：%v", err)
	}
	if err := f.FullUnban("aa:bb:cc:dd:ee:ff"); err != nil {
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

// [full_ban] allow 支持端口表达式：显式配置时以其为准（不叠加内置端口），去重后升序。
func TestFirewallFullBanAllowExpression(t *testing.T) {
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port}",
		UnbanCmd: "unban {mac} {port}",
	}, config.FullBanConfig{
		Mode:     "on",
		BanCmd:   "fullban {ports}",
		UnbanCmd: "fullunban {mac}",
		Allow:    []any{int64(53), "1000-1002"},
	}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	got := portsCSV(f.FullBanAllowPorts())
	want := "53,1000,1001,1002"
	if got != want {
		t.Fatalf("放行端口 = %q，期望 %q", got, want)
	}

	// 未配置 allow 时使用内置常用端口。
	def, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port}",
		UnbanCmd: "unban {mac} {port}",
	}, config.FullBanConfig{
		Mode:     "on",
		BanCmd:   "fullban {ports}",
		UnbanCmd: "fullunban {mac}",
	}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if got := portsCSV(def.FullBanAllowPorts()); got != "53,67,68,123,546,547" {
		t.Fatalf("未配置时应使用内置常用端口，got %q", got)
	}
}

// 封禁协议随触发协议：hook 的 {proto} 取触发协议，ban_both 下对 v4/v6 各执行一次。
func TestFirewallHookPerProtocol(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {family} {proto}",
		UnbanCmd: "unban {mac} {port} {family} {proto}",
	}, config.FullBanConfig{}, config.ProtoModeAll, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "tcp"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	for _, want := range []string{
		"sh -c ban aa:bb:cc:dd:ee:ff 40000 v4 tcp",
		"sh -c ban aa:bb:cc:dd:ee:ff 40000 v6 tcp",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("命令 %q 应执行一次，got %d：%v", want, n, rec.snapshot())
		}
	}
	if n := rec.countContains("udp"); n != 0 {
		t.Fatalf("TCP 触发不应出现 udp，got %v", rec.snapshot())
	}
}
