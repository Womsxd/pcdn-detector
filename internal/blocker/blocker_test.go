package blocker

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/logx"
	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/state"
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

func testLogger() *logx.Logger { return logx.New(io.Discard, "", 0) }

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

// Close 幂等：reload 与退出可能并发关闭同一个 Blocker，重复调用不应 panic 或重复解封。
func TestBlockerCloseIdempotent(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	b.Close()
	unbans := rec.countContains("sh -c unban ")
	if unbans != 2 {
		t.Fatalf("Close 应对 v4/v6 各解封一次（2 条），got %d", unbans)
	}

	b.Close() // 第二次不应 panic，也不应重复解封
	if got := rec.countContains("sh -c unban "); got != unbans {
		t.Fatalf("重复 Close 不应重复解封，got %d", got)
	}
}

// 补发封禁：把当前告警会话直接纳入封禁；同端口 v4/v6 合并引用，重复补发幂等。
func TestBlockerAdoptSessions(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"},
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	mac, _ := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	sessions := []state.AlertSession{
		{MAC: mac, Port: 40000, Proto: netutil.ProtoUDP, IP: netip.MustParseAddr("192.168.1.5")},
		{MAC: mac, Port: 40000, Proto: netutil.ProtoUDP, V6: true, IP: netip.MustParseAddr("2408::1")},
		{MAC: mac, Port: 40001, Proto: netutil.ProtoUDP, IP: netip.MustParseAddr("192.168.1.5")},
	}
	b.AdoptSessions(sessions)
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 4 })

	snap := b.Snapshot()
	if len(snap.Bans) != 2 {
		t.Fatalf("应补发 2 条封禁（40000 / 40001），got %d：%+v", len(snap.Bans), snap.Bans)
	}
	for _, ban := range snap.Bans {
		if ban.Port == 40000 && ban.Refs != 2 {
			t.Fatalf("同端口 v4/v6 应合并引用计数为 2，got %d", ban.Refs)
		}
	}

	// 幂等：已存在的条目不应重复下发。
	before := rec.countContains("sh -c ban ")
	b.AdoptSessions(sessions)
	time.Sleep(30 * time.Millisecond)
	if got := rec.countContains("sh -c ban "); got != before {
		t.Fatalf("重复补发不应重复下发，got %d（此前 %d）", got, before)
	}

	// 同端口一端结束仍有引用：不解封；另一端结束才解封。
	b.OnAlertEnd("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	time.Sleep(30 * time.Millisecond)
	if n := rec.countContains("unban aa:bb:cc:dd:ee:ff 40000"); n != 0 {
		t.Fatalf("仍有引用时不应解封，got %d", n)
	}
	b.OnAlertEnd("aa:bb:cc:dd:ee:ff", "2408::1", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("unban aa:bb:cc:dd:ee:ff 40000 v4") == 1 })
}

// 配置 ban_ttl 时，refreshBans 应重新 add 元素以刷新 nftables 超时。
func TestBlockerRefreshBansRenewsNftTimeout(t *testing.T) {
	rec := &cmdRecorder{}
	fw, err := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend:  "nftables",
		Nftables: config.FirewallNftablesConfig{BanTTL: config.Duration(time.Hour)},
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	b := NewBlocker(fw, testLogger(), false)
	defer b.Close()

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("timeout 3600s") == 2 })

	before := rec.countContains("timeout 3600s")
	b.refreshBans()
	if got := rec.countContains("timeout 3600s"); got != before+2 {
		t.Fatalf("续期应重新 add v4/v6 两个元素，got %d（此前 %d）：%v", got, before, rec.snapshot())
	}
}

// 未配置 ban_ttl 时续期不应产生任何命令。
func TestBlockerRefreshBansNoTTL(t *testing.T) {
	rec := &cmdRecorder{}
	fw, err := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	b := NewBlocker(fw, testLogger(), false)
	defer b.Close()

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return len(b.Snapshot().Bans) == 1 })
	before := len(rec.snapshot())
	b.refreshBans()
	if got := len(rec.snapshot()); got != before {
		t.Fatalf("未启用 ban_ttl 时续期不应下发命令，got %d 条新命令", got-before)
	}
}

// Close 与 Migrate 并发时不得因 RWMutex 写者优先而死锁：
// Close 必须先等事件协程退出，再取写锁；反过来会让正等读锁的 handle 永久阻塞。
func TestBlockerCloseWhileMigrateDoesNotDeadlock(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)

	entered := make(chan struct{})
	release := make(chan struct{})
	migrateDone := make(chan struct{})
	go func() {
		defer close(migrateDone)
		_, _ = b.Migrate(func() (*firewall.Firewall, FullBanConfig, UPnPConfig, error) {
			close(entered)
			<-release
			return f, FullBanConfig{}, UPnPConfig{}, nil
		})
	}()
	<-entered // Migrate 已持有写锁

	// 事件协程取事件后会阻塞在 handle 的读锁上。
	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return len(b.events) == 0 })
	time.Sleep(20 * time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		b.Close()
		close(closeDone)
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)

	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Close 与 Migrate 并发时发生死锁")
	}
	<-migrateDone
}

// Migrate 原地换后端：先解封旧后端，再按快照在新后端重新下发；对象与内存状态保持有效。
func TestBlockerMigrateReappliesState(t *testing.T) {
	oldRec := &cmdRecorder{}
	oldFw, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "old {action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), oldRec.run)
	b := NewBlocker(oldFw, testLogger(), false)
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return oldRec.countContains("old ban ") == 2 })

	newRec := &cmdRecorder{}
	newFw, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "new {action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), newRec.run)
	gotFw, err := b.Migrate(func() (*firewall.Firewall, FullBanConfig, UPnPConfig, error) {
		return newFw, FullBanConfig{}, UPnPConfig{}, nil
	})
	if err != nil {
		t.Fatalf("Migrate 失败：%v", err)
	}
	if gotFw != newFw {
		t.Fatal("Migrate 应返回新防火墙对象")
	}

	// 旧后端逐条解封（v4/v6 各一条），新后端按快照同步重新下发。
	if n := oldRec.countContains("old unban "); n != 2 {
		t.Fatalf("旧后端应解封 2 条，got %d", n)
	}
	if n := newRec.countContains("new ban "); n != 2 {
		t.Fatalf("新后端应重新封禁 2 条，got %d", n)
	}
	if n := len(b.Snapshot().Bans); n != 1 {
		t.Fatalf("迁移后应保留 1 条封禁状态，got %d", n)
	}

	// 迁移后的结束事件应走新后端解封。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return newRec.countContains("new unban ") == 2 })
}

// Migrate 失败时应保留内存状态，供调用方保存后回退重启。
func TestBlockerMigrateFailureKeepsState(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })

	if _, err := b.Migrate(func() (*firewall.Firewall, FullBanConfig, UPnPConfig, error) {
		return nil, FullBanConfig{}, UPnPConfig{}, errors.New("build failed")
	}); err == nil {
		t.Fatal("build 失败时 Migrate 应返回错误")
	}
	if n := len(b.Snapshot().Bans); n != 1 {
		t.Fatalf("迁移失败后应保留内存状态，got %d 条", n)
	}
}

// 默认（ban_both=true）：同一「MAC + 端口」的 v4/v6 重复触发只封一次（引用计数），
// 每次封禁对 v4/v6 各下发一条命令；不同端口分别封禁与解封。
func TestBlockerPerPort(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
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
		Backend: "hook",
		BanBoth: boolPtr(false),
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"},
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
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
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {proto}"},
	}, config.FullBanConfig{}, config.ProtoModeAll, testLogger(), rec.run)
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

// fullHookFirewall 构建一个启用全端口封禁的 hook 防火墙，用于 blocker 测试。
func fullHookFirewall(t *testing.T, rec *cmdRecorder) *firewall.Firewall {
	t.Helper()
	f, err := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{Cmd: "full {action} {mac} {ports}"},
	}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	return f
}

// 全端口封禁（on）：设备被封禁端口数达到阈值即触发全 UDP 端口封禁；
// 归零时自动解除；未达阈值或仍有端口被封禁时均不触发 / 不解除。
func TestBlockerFullBanOn(t *testing.T) {
	rec := &cmdRecorder{}
	f := fullHookFirewall(t, rec)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 2})
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })
	// 仅 1 个端口被封禁（< 阈值 2），不应触发全端口封禁。
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c full ban "); n != 0 {
		t.Fatalf("未达阈值不应触发全端口封禁，got %d", n)
	}

	// 第 2 个端口被封禁：达到阈值，触发全端口封禁（对 v4/v6 各执行一次）。
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full ban aa:bb:cc:dd:ee:ff ") == 2 })

	// 解除一个端口：仍有 1 个端口被封禁，不应解除全端口封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c full unban "); n != 0 {
		t.Fatalf("仍有被封禁端口时不应解除全端口封禁，got %d", n)
	}

	// 解除最后一个端口：端口计数归零，解除全端口封禁（对 v4/v6 各执行一次）。
	b.OnAlertEnd(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full unban aa:bb:cc:dd:ee:ff") == 2 })
}

// 设备触发全端口封禁后，新触发的端口不再单独下发端口级封禁规则（其流量已被设备级全封禁覆盖）；
// 对应解封也应跳过，且全端口封禁需在该设备告警全部结束前保持有效。
func TestBlockerFullBanSkipsNewPort(t *testing.T) {
	rec := &cmdRecorder{}
	f := fullHookFirewall(t, rec)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 1})
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	// 第一个端口：先单独封禁（v4/v6 各一条），随即达到阈值触发全端口封禁（v4/v6 各一条）。
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full ban aa:bb:cc:dd:ee:ff") == 2 })
	if n := rec.countContains("sh -c ban aa:bb:cc:dd:ee:ff 40000"); n != 2 {
		t.Fatalf("40000 应在触发全封禁前单独封禁一次（v4/v6），got %d：%v", n, rec.snapshot())
	}

	// 全端口封禁期间新触发的端口：不应再下发端口级封禁规则。
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c ban aa:bb:cc:dd:ee:ff 40001"); n != 0 {
		t.Fatalf("全端口封禁后不应再单独封禁新端口，got %d：%v", n, rec.snapshot())
	}

	// 结束新端口：未单独封禁，不应产生解封命令；此时仍有告警端口，全端口封禁保持。
	b.OnAlertEnd(mac, "192.168.1.5", 40001, "udp")
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001"); n != 0 {
		t.Fatalf("未单独封禁的端口不应产生解封命令，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c full unban "); n != 0 {
		t.Fatalf("仍有被封禁端口时不应解除全端口封禁，got %d", n)
	}

	// 结束最后一个端口：端口计数归零，解除全端口封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full unban aa:bb:cc:dd:ee:ff") == 2 })
}

// 全端口封禁生效后，应移除该设备此前按端口单独下发的冗余 UDP 规则（已被全封禁覆盖），
// 且该端口告警结束时不再重复解封；TCP 端口不在全 UDP 封禁范围内，其端口级规则应保留。
func TestBlockerFullBanRemovesRedundantPortRules(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {proto}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{Cmd: "full {action} {mac}"},
	}, config.ProtoModeAll, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 2})
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	// 两个不同端口（UDP 40000、TCP 40001）达到阈值 2，各自先单独封禁。
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "192.168.1.5", 40001, "tcp")
	waitFor(t, func() bool { return rec.countContains("sh -c full ban aa:bb:cc:dd:ee:ff") == 2 })

	// 冗余的 UDP 端口规则应被移除（v4/v6 各一条）。
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 udp") == 2 })
	// TCP 端口不在全 UDP 封禁范围内，不应被移除。
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001 tcp"); n != 0 {
		t.Fatalf("TCP 端口不在全 UDP 封禁范围内，不应被移除，got %d：%v", n, rec.snapshot())
	}

	// 结束 UDP 40000：规则已在触发全封禁时移除，不应再次解封。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40000 udp"); n != 2 {
		t.Fatalf("UDP 端口规则应仅移除一次，got %d：%v", n, rec.snapshot())
	}

	// 结束 TCP 40001：保留的端口规则正常解封。
	b.OnAlertEnd(mac, "192.168.1.5", 40001, "tcp")
	waitFor(t, func() bool { return rec.countContains("sh -c unban aa:bb:cc:dd:ee:ff 40001 tcp") == 2 })
}

// 同一端口的 IPv4 / IPv6 重复触发只计为一个端口（引用计数），不应提前达到阈值。
// 使用 ban_both=false 使 v4 与 v6 成为两个独立条目，从而真正考验端口去重。
func TestBlockerFullBanPortRefCount(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		BanBoth: boolPtr(false),
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{Cmd: "full {action} {mac}"},
	}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 2})
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "2408::1", 40000, "udp") // 同一端口的另一个地址族
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c full ban "); n != 0 {
		t.Fatalf("同一端口的 v4/v6 只应计为一个端口，不应触发全端口封禁，got %d", n)
	}

	// 第二个端口触发。
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full ban aa:bb:cc:dd:ee:ff") == 2 })
}

// 全端口封禁（device）：仅对 FullBanConfig.Devices 中列出的设备生效。
func TestBlockerFullBanDeviceMode(t *testing.T) {
	rec := &cmdRecorder{}
	f := fullHookFirewall(t, rec)
	fb := FullBanConfig{
		Enabled:   true,
		Mode:      config.FullBanDevice,
		Threshold: 1,
		Devices:   map[string]struct{}{"aa:bb:cc:dd:ee:ff": {}},
	}
	b := NewBlockerWithFullBan(f, testLogger(), false, fb)
	defer b.Close()

	// 未列出的设备：即使达到阈值也不触发。
	b.OnAlertStart("11:22:33:44:55:66", "192.168.1.6", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c full ban "); n != 0 {
		t.Fatalf("device 模式下未列出的设备不应触发全端口封禁，got %d", n)
	}

	// 列出的设备：触发。
	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full ban aa:bb:cc:dd:ee:ff") == 2 })
}

// 退出时对仍处于全端口封禁的设备兜底解除。
func TestBlockerFullBanClose(t *testing.T) {
	rec := &cmdRecorder{}
	f := fullHookFirewall(t, rec)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 1})

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c full ban aa:bb:cc:dd:ee:ff") == 2 })

	b.Close()
	if n := rec.countContains("sh -c full unban aa:bb:cc:dd:ee:ff"); n != 2 {
		t.Fatalf("退出时应解除全端口封禁，got %d：%v", n, rec.snapshot())
	}
}

// 退出时对仍封禁中的条目兜底解封。
func TestBlockerCloseUnbans(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
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

// upnpHookFirewall 构建一个启用 UPnP 拦截的 hook 防火墙，用于 blocker 测试。
func upnpHookFirewall(t *testing.T, rec *cmdRecorder) *firewall.Firewall {
	t.Helper()
	f, err := firewall.NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{
		Mode: "on",
		Hook: config.UPnPHookConfig{Cmd: "upnp {action} {mac} {ports}"},
	}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	return f
}

// upnpBlockAllHookFirewall 构建一个启用 UPnP 白名单模式（全量拦截 + 放行）的 hook 防火墙。
func upnpBlockAllHookFirewall(t *testing.T, rec *cmdRecorder) *firewall.Firewall {
	t.Helper()
	f, err := firewall.NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{
		Mode: "on",
		Hook: config.UPnPHookConfig{Cmd: "upnp {action} {mac} {ports}"},
	}, config.UPnPFilter{BlockAll: true, Devices: []string{"aa:bb:cc:dd:ee:ff"}}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	return f
}

// UPnP 拦截：启动时对目标设备立即拦截（静态），退出时兜底解除；
// 未启用时不做任何操作。
func TestBlockerUPnP(t *testing.T) {
	rec := &cmdRecorder{}
	f := upnpHookFirewall(t, rec)
	b := NewBlockerWithUPnP(f, testLogger(), false, FullBanConfig{}, UPnPConfig{
		Enabled: true,
		Mode:    config.UPnPOn,
		Targets: []string{"aa:bb:cc:dd:ee:ff"},
	})
	// 静态拦截在构造时同步完成（对 v4/v6 各执行一次）。
	if n := rec.countContains("sh -c upnp ban aa:bb:cc:dd:ee:ff 1900,5000"); n != 2 {
		t.Fatalf("启动时应立即拦截目标设备的 UPnP，got %d：%v", n, rec.snapshot())
	}

	b.Close()
	if n := rec.countContains("sh -c upnp unban aa:bb:cc:dd:ee:ff 1900,5000"); n != 2 {
		t.Fatalf("退出时应解除 UPnP 拦截，got %d：%v", n, rec.snapshot())
	}
}

// 未启用 UPnP 拦截时不应对任何设备下发命令。
func TestBlockerUPnPDisabled(t *testing.T) {
	rec := &cmdRecorder{}
	f := upnpHookFirewall(t, rec)
	b := NewBlockerWithUPnP(f, testLogger(), false, FullBanConfig{}, UPnPConfig{Targets: []string{"aa:bb:cc:dd:ee:ff"}})
	b.Close()
	if n := rec.countContains("sh -c upnp "); n != 0 {
		t.Fatalf("未启用 UPnP 拦截时不应下发命令，got %v", rec.snapshot())
	}
}

// UPnP 白名单模式：启动时先拦截全部，再为名单设备放行；退出时先取消放行，再解除全部拦截。
func TestBlockerUPnPBlockAll(t *testing.T) {
	rec := &cmdRecorder{}
	f := upnpBlockAllHookFirewall(t, rec)
	b := NewBlockerWithUPnP(f, testLogger(), false, FullBanConfig{}, UPnPConfig{
		Enabled:  true,
		Mode:     config.UPnPOn,
		BlockAll: true,
		Targets:  []string{"aa:bb:cc:dd:ee:ff"},
	})
	// 静态应用在构造时同步完成（对 v4/v6 各执行一次）。
	if n := rec.countContains("sh -c upnp block-all"); n != 2 {
		t.Fatalf("启动时应拦截全部 UPnP，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c upnp allow aa:bb:cc:dd:ee:ff 1900,5000"); n != 2 {
		t.Fatalf("启动时应对名单设备放行，got %d：%v", n, rec.snapshot())
	}

	b.Close()
	if n := rec.countContains("sh -c upnp disallow aa:bb:cc:dd:ee:ff 1900,5000"); n != 2 {
		t.Fatalf("退出时应取消放行，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c upnp unblock-all"); n != 2 {
		t.Fatalf("退出时应解除全部拦截，got %d：%v", n, rec.snapshot())
	}
}

// BanIndex 应按「端口 + 协议 + 地址族」判定封禁状态；ban_both=false 时不同地址族互不影响。
func TestBanIndexByFamilyAndProto(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		BanBoth: boolPtr(false),
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"},
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return len(b.BanIndex().Rules) == 1 })

	ix := b.BanIndex()
	if !ix.Banned(mac, 40000, "udp", false) {
		t.Fatal("v4 触发的 UDP 端口应为封禁")
	}
	if ix.Banned(mac, 40000, "udp", true) {
		t.Fatal("ban_both=false 时 v4 封禁不应覆盖 v6")
	}
	if ix.Banned(mac, 40001, "udp", false) {
		t.Fatal("未封禁端口不应判定为封禁")
	}
	if ix.Banned(mac, 40000, "tcp", false) {
		t.Fatal("UDP 封禁不应覆盖 TCP")
	}
	if ix.FullBanned(mac) {
		t.Fatal("未启用全端口封禁时 FullBanned 应为 false")
	}
}

// 全 UDP 端口封禁生效时，该设备所有 UDP 端口（v4/v6）均视为封禁，TCP 不受影响。
func TestBanIndexFullBan(t *testing.T) {
	rec := &cmdRecorder{}
	f := fullHookFirewall(t, rec)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 1})
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return b.BanIndex().FullBanned(mac) })

	ix := b.BanIndex()
	if !ix.Banned(mac, 12345, "udp", true) || !ix.Banned(mac, 12345, "udp", false) {
		t.Fatal("全 UDP 端口封禁应覆盖该设备所有 UDP 端口（含 v4/v6）")
	}
	if ix.Banned(mac, 12345, "tcp", false) {
		t.Fatal("全 UDP 端口封禁不应覆盖 TCP")
	}
	if !ix.Banned(mac, 40000, "udp", false) {
		t.Fatal("已封禁的触发端口应为封禁")
	}
	// 53 是内置放行端口（full_ban.allow 默认值），设备级全封禁下仍放行。
	if ix.Banned(mac, 53, "udp", false) {
		t.Fatal("全端口封禁的放行端口不应判定为封禁")
	}
}

// Counts 的计数口径必须与 Snapshot 各切片的长度一致，且不构造条目副本。
func TestBlockerCounts(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"},
	}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return b.Counts().ActiveBans == 2 })

	c := b.Counts()
	s := b.Snapshot()
	if c.ActiveBans != len(s.Bans) || c.FullBanned != len(s.FullBanned) ||
		c.UPnPBlocked != len(s.UPnPBlocked) || c.UPnPAllowed != len(s.UPnPAllowed) ||
		c.UPnPAll != s.UPnPAll {
		t.Fatalf("Counts 与 Snapshot 不一致：counts=%+v snapshot=%+v", c, s)
	}
	if c.ActiveBans != 2 {
		t.Fatalf("ActiveBans 应为 2，got %d", c.ActiveBans)
	}
}

// 静态应用的 UPnP 拦截也应计入 Counts。
func TestBlockerCountsUPnP(t *testing.T) {
	rec := &cmdRecorder{}
	f := upnpHookFirewall(t, rec)
	b := NewBlockerWithUPnP(f, testLogger(), false, FullBanConfig{}, UPnPConfig{
		Enabled: true,
		Mode:    config.UPnPOn,
		Targets: []string{"aa:bb:cc:dd:ee:ff"},
	})
	defer b.Close()

	c := b.Counts()
	s := b.Snapshot()
	if c.UPnPBlocked != 1 || c.UPnPBlocked != len(s.UPnPBlocked) {
		t.Fatalf("UPnPBlocked 应为 1（counts=%d snapshot=%d）", c.UPnPBlocked, len(s.UPnPBlocked))
	}
}
