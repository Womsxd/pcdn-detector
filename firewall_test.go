package main

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
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
	f, err := newFirewall(FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {ip} {port} {family}",
		UnbanCmd: "unban {mac} {ip} {port} {family}",
	}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}

	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
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
	f, err := newFirewall(FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {family}",
		UnbanCmd: "unban {mac} {port} {family}",
		BanBoth:  boolPtr(false),
	}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}

	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "2408::1", 40000); err != nil {
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
	if _, err := newFirewall(FirewallConfig{Backend: "hook"}, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("hook 后端缺少命令应报错")
	}
}

func TestFirewallUnknownBackend(t *testing.T) {
	if _, err := newFirewall(FirewallConfig{Backend: "iptables2"}, testLogger(), (&cmdRecorder{}).run); err == nil {
		t.Fatalf("未知后端应报错")
	}
}

// iptables 后端：默认同时封禁，按源 MAC + UDP 源端口分别对 iptables/ip6tables 操作。
func TestFirewallIptables(t *testing.T) {
	rec := &cmdRecorder{failCheck: true}
	f, err := newFirewall(FirewallConfig{Backend: "iptables"}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
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
	f, err := newFirewall(FirewallConfig{Backend: "iptables", BanBoth: boolPtr(false)}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
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
	f, _ := newFirewall(FirewallConfig{Backend: "iptables"}, testLogger(), rec.run)
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if n := rec.countContains("-I FORWARD"); n != 0 {
		t.Fatalf("规则已存在时不应重复插入，got %v", rec.snapshot())
	}
}

// nftables 后端：初始化 v4/v6 两个拼接集合与各自规则；默认封禁时两个集合各加一个元素。
func TestFirewallNftables(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(FirewallConfig{Backend: "nftables"}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if rec.countContains("add set bridge pcdn_detect banned_v4 { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化 v4 拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add set bridge pcdn_detect banned_v6 { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化 v6 拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect forward ether type ip ip protocol udp ether saddr . udp sport @banned_v4 drop") != 1 {
		t.Fatalf("应初始化 IPv4 规则，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect forward ether type ip6 ip6 nexthdr udp ether saddr . udp sport @banned_v6 drop") != 1 {
		t.Fatalf("应初始化 IPv6 规则，got %v", rec.snapshot())
	}

	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if rec.countContains("nft add element bridge pcdn_detect banned_v4 { aa:bb:cc:dd:ee:ff . 40000 }") != 1 ||
		rec.countContains("nft add element bridge pcdn_detect banned_v6 { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("默认应同时封禁 v4/v6，命令不符：%v", rec.snapshot())
	}
	if rec.countContains("nft delete element bridge pcdn_detect banned_v4 { aa:bb:cc:dd:ee:ff . 40000 }") != 1 ||
		rec.countContains("nft delete element bridge pcdn_detect banned_v6 { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("默认应同时解封 v4/v6，命令不符：%v", rec.snapshot())
	}
}

// ban_both=false：v4 触发时元素只加入 banned_v4。
func TestFirewallNftablesSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(FirewallConfig{Backend: "nftables", BanBoth: boolPtr(false)}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if rec.countContains("nft add element bridge pcdn_detect banned_v4 { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("v4 触发应加入 banned_v4，got %v", rec.snapshot())
	}
	if n := rec.countContains("banned_v6 { aa:bb:cc"); n != 0 {
		t.Fatalf("v4 触发不应加入 banned_v6，got %v", rec.snapshot())
	}
}

// 退出时（Cleanup）应删除整张 nftables 表，连带链、集合与规则一并清除。
func TestFirewallCleanupNftables(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(FirewallConfig{Backend: "nftables"}, testLogger(), rec.run)
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
	f, err := newFirewall(FirewallConfig{Backend: "iptables"}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	f.Cleanup()
	if n := rec.countContains("delete table"); n != 0 {
		t.Fatalf("iptables 后端不应删除表，got %v", rec.snapshot())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待条件超时")
}

// 默认（ban_both=true）：同一「MAC + 端口」的 v4/v6 重复触发只封一次（引用计数），
// 每次封禁对 v4/v6 各下发一条命令；不同端口分别封禁与解封。
func TestBlockerPerPort(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := newFirewall(FirewallConfig{Backend: "hook", BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"}, testLogger(), rec.run)
	b := NewBlocker(f, testLogger())
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	// 同 MAC + 端口，IPv4 与 IPv6 各触发一次 -> 引用计数为 2，只封一次（2 条命令）。
	b.OnAlertStart(mac, "192.168.1.5", 40000)
	b.OnAlertStart(mac, "2408::1", 40000)
	// 另一个端口 -> 独立封禁。
	b.OnAlertStart(mac, "192.168.1.5", 40001)
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 4 })

	// 结束 40000 中的一个地址族：仍有引用，不应解封。
	b.OnAlertEnd(mac, "192.168.1.5", 40000)
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c unban "); n != 0 {
		t.Fatalf("仍有引用时不应解封，got %d 次", n)
	}

	// 结束 40000 的另一引用：解封 40000（v4/v6 各一条）。
	b.OnAlertEnd(mac, "2408::1", 40000)
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v4") == 1 })
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6") == 1 })

	// 40001 结束：解封 40001。
	b.OnAlertEnd(mac, "192.168.1.5", 40001)
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001 v4") == 1 })
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001 v6") == 1 })
}

// ban_both=false：同一「MAC + 端口」的 v4 与 v6 各自独立封禁 / 解封。
func TestBlockerSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := newFirewall(FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {family}",
		UnbanCmd: "unban {mac} {port} {family}",
		BanBoth:  boolPtr(false),
	}, testLogger(), rec.run)
	b := NewBlocker(f, testLogger())
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000)
	b.OnAlertStart(mac, "2408::1", 40000)
	// v4、v6 各自独立封禁 -> 共两条命令。
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	// 结束 v4：仅解封 v4，v6 仍封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40000)
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v4") == 1 })
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6"); n != 0 {
		t.Fatalf("结束 v4 不应解封 v6，got %d 次", n)
	}

	// 结束 v6：解封 v6。
	b.OnAlertEnd(mac, "2408::1", 40000)
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6") == 1 })
}

// 退出时对仍封禁中的条目兜底解封。
func TestBlockerCloseUnbans(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := newFirewall(FirewallConfig{Backend: "hook", BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"}, testLogger(), rec.run)
	b := NewBlocker(f, testLogger())

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000)
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	b.Close()
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v4"); n != 1 {
		t.Fatalf("退出时应解封 v4，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6"); n != 1 {
		t.Fatalf("退出时应解封 v6，got %d 次：%v", n, rec.snapshot())
	}
}

type fakeSink struct {
	starts []string
	ends   []string
}

func (s *fakeSink) OnAlertStart(mac, ip string, port uint16) {
	s.starts = append(s.starts, fmt.Sprintf("%s:%d", mac, port))
}
func (s *fakeSink) OnAlertEnd(mac, ip string, port uint16) {
	s.ends = append(s.ends, fmt.Sprintf("%s:%d", mac, port))
}

// 检测层应在告警开始 / 结束时回调 sink。
func TestDetectorNotifiesSink(t *testing.T) {
	d, buf := newTestDetector(2, time.Minute, 10*time.Minute)
	sink := &fakeSink{}
	d.SetSink(sink)
	base := time.Now()

	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.100", 40000, []string{"1.1.1.1", "2.2.2.2"}, base)
	buf.Reset()
	d.Scan(base)
	if len(sink.starts) != 1 || sink.starts[0] != "aa:bb:cc:dd:ee:ff:40000" {
		t.Fatalf("应回调告警开始，got %v", sink.starts)
	}

	// 超过 alertDuration 后本轮结束。
	d.Scan(base.Add(11 * time.Minute))
	if len(sink.ends) != 1 || sink.ends[0] != "aa:bb:cc:dd:ee:ff:40000" {
		t.Fatalf("应回调告警结束，got %v", sink.ends)
	}
}
