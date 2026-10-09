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
	}, config.ProtoModeUDP, testLogger(), rec.run)
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
	}, config.ProtoModeUDP, testLogger(), rec.run)
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
	if _, err := newFirewall(config.FirewallConfig{Backend: "hook"}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("hook 后端缺少命令应报错")
	}
}

func TestFirewallUnknownBackend(t *testing.T) {
	if _, err := newFirewall(config.FirewallConfig{Backend: "iptables2"}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("未知后端应报错")
	}
}

// iptables 后端：默认同时封禁，按源 MAC + UDP 源端口分别对 iptables/ip6tables 操作。
func TestFirewallIptables(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.ProtoModeUDP, testLogger(), rec.run)
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
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables", BanBoth: boolPtr(false)}, config.ProtoModeUDP, testLogger(), rec.run)
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
	f, _ := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.ProtoModeUDP, testLogger(), rec.run)
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
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if rec.countContains("add set bridge pcdn_detect banned_v4_udp { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化 v4 UDP 拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add set bridge pcdn_detect banned_v6_udp { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化 v6 UDP 拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect forward ether type ip ip protocol udp ether saddr . udp sport @banned_v4_udp drop") != 1 {
		t.Fatalf("应初始化 IPv4 UDP 规则，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect forward ether type ip6 ip6 nexthdr udp ether saddr . udp sport @banned_v6_udp drop") != 1 {
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

// ban_both=false：v4 触发时元素只加入 banned_v4_udp。
func TestFirewallNftablesSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables", BanBoth: boolPtr(false)}, config.ProtoModeUDP, testLogger(), rec.run)
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
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.ProtoModeUDP, testLogger(), rec.run)
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
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.ProtoModeUDP, testLogger(), rec.run)
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
	f, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.ProtoModeAll, testLogger(), udpRec.run)
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
	f2, err := newFirewall(config.FirewallConfig{Backend: "iptables"}, config.ProtoModeAll, testLogger(), tcpRec.run)
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
	if _, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.ProtoModeAll, testLogger(), rec.run); err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	for _, want := range []string{
		"add set bridge pcdn_detect banned_v4_udp { type ether_addr . inet_service ; }",
		"add set bridge pcdn_detect banned_v4_tcp { type ether_addr . inet_service ; }",
		"add set bridge pcdn_detect banned_v6_udp { type ether_addr . inet_service ; }",
		"add set bridge pcdn_detect banned_v6_tcp { type ether_addr . inet_service ; }",
		"add rule bridge pcdn_detect forward ether type ip ip protocol udp ether saddr . udp sport @banned_v4_udp drop",
		"add rule bridge pcdn_detect forward ether type ip ip protocol tcp ether saddr . tcp sport @banned_v4_tcp drop",
		"add rule bridge pcdn_detect forward ether type ip6 ip6 nexthdr udp ether saddr . udp sport @banned_v6_udp drop",
		"add rule bridge pcdn_detect forward ether type ip6 ip6 nexthdr tcp ether saddr . tcp sport @banned_v6_tcp drop",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("应初始化 %q，got %d：%v", want, n, rec.snapshot())
		}
	}
}

// 封禁协议随触发协议：UDP 触发只加入 UDP 集合，不触碰 TCP 集合。
func TestFirewallNftablesPerProtocol(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.ProtoModeAll, testLogger(), rec.run)
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

// 封禁协议随触发协议：hook 的 {proto} 取触发协议，ban_both 下对 v4/v6 各执行一次。
func TestFirewallHookPerProtocol(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {family} {proto}",
		UnbanCmd: "unban {mac} {port} {family} {proto}",
	}, config.ProtoModeAll, testLogger(), rec.run)
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
