package blocker

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/firewall"
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
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	// 同 MAC + 端口，IPv4 与 IPv6 各触发一次 -> 引用计数为 2，只封一次（2 条命令）。
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "2408::1", 40000, "udp")
	// 另一个端口 -> 独立封禁。
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 4 })

	// 结束 40000 中的一个地址族：仍有引用，不应解封。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c unban "); n != 0 {
		t.Fatalf("仍有引用时不应解封，got %d 次", n)
	}

	// 结束 40000 的另一引用：解封 40000（v4/v6 各一条）。
	b.OnAlertEnd(mac, "2408::1", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v4") == 1 })
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6") == 1 })

	// 40001 结束：解封 40001。
	b.OnAlertEnd(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001 v4") == 1 })
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001 v6") == 1 })
}

// ban_both=false：同一「MAC + 端口」的 v4 与 v6 各自独立封禁 / 解封。
func TestBlockerSeparateFamily(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {family}",
		UnbanCmd: "unban {mac} {port} {family}",
		BanBoth:  boolPtr(false),
	}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "2408::1", 40000, "udp")
	// v4、v6 各自独立封禁 -> 共两条命令。
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	// 结束 v4：仅解封 v4，v6 仍封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v4") == 1 })
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6"); n != 0 {
		t.Fatalf("结束 v4 不应解封 v6，got %d 次", n)
	}

	// 结束 v6：解封 v6。
	b.OnAlertEnd(mac, "2408::1", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6") == 1 })
}

// 同一「MAC + 端口」的 UDP 与 TCP 各自独立封禁 / 解封（UDP 触发只封 UDP，TCP 触发只封 TCP）。
func TestBlockerPerProtocol(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend:  "hook",
		BanCmd:   "ban {mac} {port} {proto}",
		UnbanCmd: "unban {mac} {port} {proto}",
	}, config.ProtoModeAll, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "192.168.1.5", 40000, "tcp")
	// ban_both=true 下，udp 与 tcp 各对 v4/v6 一次 -> 共 4 条命令。
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 4 })
	if n := rec.countContains("sh -c ban aa:bb:cc:dd:ee:ff 40000 udp"); n != 2 {
		t.Fatalf("UDP 应对 v4/v6 各封一次，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c ban aa:bb:cc:dd:ee:ff 40000 tcp"); n != 2 {
		t.Fatalf("TCP 应对 v4/v6 各封一次，got %d：%v", n, rec.snapshot())
	}

	// 结束 UDP：只解封 UDP，TCP 仍封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 udp") == 2 })
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 tcp"); n != 0 {
		t.Fatalf("结束 UDP 不应解封 TCP，got %d：%v", n, rec.snapshot())
	}
}

// 退出时对仍封禁中的条目兜底解封。
func TestBlockerCloseUnbans(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	b.Close()
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v4"); n != 1 {
		t.Fatalf("退出时应解封 v4，got %d 次：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 v6"); n != 1 {
		t.Fatalf("退出时应解封 v6，got %d 次：%v", n, rec.snapshot())
	}
}
