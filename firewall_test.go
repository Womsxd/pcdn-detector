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

func TestFirewallHook(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {ip} {port}",
		UnbanCmd: "unban {mac} {ip} {port}",
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
		"sh -c ban aa:bb:cc:dd:ee:ff 192.168.1.5 40000",
		"sh -c unban aa:bb:cc:dd:ee:ff 192.168.1.5 40000",
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

// iptables 后端：按源 MAC + UDP 源端口封禁；规则不存在时插入，解封用 -D。
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

// nftables 后端：初始化拼接集合与两条规则，封禁/解封以「MAC . 端口」为元素。
func TestFirewallNftables(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(FirewallConfig{Backend: "nftables"}, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if rec.countContains("add set bridge pcdn_detect banned { type ether_addr . inet_service ; }") != 1 {
		t.Fatalf("应初始化拼接集合，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect forward ether type ip ip protocol udp ether saddr . udp sport @banned drop") != 1 {
		t.Fatalf("应初始化 IPv4 规则，got %v", rec.snapshot())
	}
	if rec.countContains("add rule bridge pcdn_detect forward ether type ip6 ip6 nexthdr udp ether saddr . udp sport @banned drop") != 1 {
		t.Fatalf("应初始化 IPv6 规则，got %v", rec.snapshot())
	}

	if err := f.Ban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := f.Unban("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if rec.countContains("nft add element bridge pcdn_detect banned { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("封禁命令不符：%v", rec.snapshot())
	}
	if rec.countContains("nft delete element bridge pcdn_detect banned { aa:bb:cc:dd:ee:ff . 40000 }") != 1 {
		t.Fatalf("解封命令不符：%v", rec.snapshot())
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

// 同一「MAC + 端口」重复触发只封一次（引用计数）；不同端口分别封禁与解封。
func TestBlockerPerPort(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := newFirewall(FirewallConfig{Backend: "hook", BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"}, testLogger(), rec.run)
	b := NewBlocker(f, testLogger())
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	// 同 MAC + 端口，IPv4 与 IPv6 各触发一次 -> 引用计数为 2，只封一次。
	b.OnAlertStart(mac, "192.168.1.5", 40000)
	b.OnAlertStart(mac, "2408::1", 40000)
	// 另一个端口 -> 独立封禁。
	b.OnAlertStart(mac, "192.168.1.5", 40001)
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	// 结束 40000 中的一个地址族：仍有引用，不应解封。
	b.OnAlertEnd(mac, "192.168.1.5", 40000)
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c unban "); n != 0 {
		t.Fatalf("仍有引用时不应解封，got %d 次", n)
	}

	// 结束 40000 的另一引用：解封 40000。
	b.OnAlertEnd(mac, "2408::1", 40000)
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000") == 1 })

	// 40001 结束：解封 40001。
	b.OnAlertEnd(mac, "192.168.1.5", 40001)
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001") == 1 })
}

// 退出时对仍封禁中的条目兜底解封。
func TestBlockerCloseUnbans(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := newFirewall(FirewallConfig{Backend: "hook", BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"}, testLogger(), rec.run)
	b := NewBlocker(f, testLogger())

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000)
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 1 })

	b.Close()
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000"); n != 1 {
		t.Fatalf("退出时应解封，got %d 次：%v", n, rec.snapshot())
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
