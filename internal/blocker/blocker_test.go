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
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"},
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port} {proto}", UnbanCmd: "unban {mac} {port} {proto}"},
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{BanCmd: "fullban {mac} {ports}", UnbanCmd: "fullunban {mac}"},
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
	if n := rec.countContains("sh -c fullban "); n != 0 {
		t.Fatalf("未达阈值不应触发全端口封禁，got %d", n)
	}

	// 第 2 个端口被封禁：达到阈值，触发全端口封禁。
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c fullban aa:bb:cc:dd:ee:ff ") == 1 })

	// 解除一个端口：仍有 1 个端口被封禁，不应解除全端口封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40000, "udp")
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c fullunban "); n != 0 {
		t.Fatalf("仍有被封禁端口时不应解除全端口封禁，got %d", n)
	}

	// 解除最后一个端口：端口计数归零，解除全端口封禁。
	b.OnAlertEnd(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c fullunban aa:bb:cc:dd:ee:ff") == 1 })
}

// 同一端口的 IPv4 / IPv6 重复触发只计为一个端口（引用计数），不应提前达到阈值。
// 使用 ban_both=false 使 v4 与 v6 成为两个独立条目，从而真正考验端口去重。
func TestBlockerFullBanPortRefCount(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{
		Backend: "hook",
		BanBoth: boolPtr(false),
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{BanCmd: "fullban {mac}", UnbanCmd: "fullunban {mac}"},
	}, config.ProtoModeUDP, testLogger(), rec.run)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 2})
	defer b.Close()

	const mac = "aa:bb:cc:dd:ee:ff"
	b.OnAlertStart(mac, "192.168.1.5", 40000, "udp")
	b.OnAlertStart(mac, "2408::1", 40000, "udp") // 同一端口的另一个地址族
	waitFor(t, func() bool { return rec.countContains("sh -c ban ") == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := rec.countContains("sh -c fullban "); n != 0 {
		t.Fatalf("同一端口的 v4/v6 只应计为一个端口，不应触发全端口封禁，got %d", n)
	}

	// 第二个端口触发。
	b.OnAlertStart(mac, "192.168.1.5", 40001, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c fullban aa:bb:cc:dd:ee:ff") == 1 })
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
	if n := rec.countContains("sh -c fullban "); n != 0 {
		t.Fatalf("device 模式下未列出的设备不应触发全端口封禁，got %d", n)
	}

	// 列出的设备：触发。
	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c fullban aa:bb:cc:dd:ee:ff") == 1 })
}

// 退出时对仍处于全端口封禁的设备兜底解除。
func TestBlockerFullBanClose(t *testing.T) {
	rec := &cmdRecorder{}
	f := fullHookFirewall(t, rec)
	b := NewBlockerWithFullBan(f, testLogger(), false, FullBanConfig{Enabled: true, Mode: config.FullBanOn, Threshold: 1})

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.5", 40000, "udp")
	waitFor(t, func() bool { return rec.countContains("sh -c fullban aa:bb:cc:dd:ee:ff") == 1 })

	b.Close()
	if n := rec.countContains("sh -c fullunban aa:bb:cc:dd:ee:ff"); n != 1 {
		t.Fatalf("退出时应解除全端口封禁，got %d：%v", n, rec.snapshot())
	}
}

// 退出时对仍封禁中的条目兜底解封。
func TestBlockerCloseUnbans(t *testing.T) {
	rec := &cmdRecorder{}
	f, _ := firewall.NewFirewallWithRunner(config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"}}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{
		Mode: "on",
		Hook: config.UPnPHookConfig{BanCmd: "upnpban {mac} {ports}", UnbanCmd: "upnpunban {mac}"},
	}, config.ProtoModeUDP, testLogger(), rec.run)
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
	// 静态拦截在构造时同步完成。
	if n := rec.countContains("sh -c upnpban aa:bb:cc:dd:ee:ff 1900,5000"); n != 1 {
		t.Fatalf("启动时应立即拦截目标设备的 UPnP，got %d：%v", n, rec.snapshot())
	}

	b.Close()
	if n := rec.countContains("sh -c upnpunban aa:bb:cc:dd:ee:ff"); n != 1 {
		t.Fatalf("退出时应解除 UPnP 拦截，got %d：%v", n, rec.snapshot())
	}
}

// 未启用 UPnP 拦截时不应对任何设备下发命令。
func TestBlockerUPnPDisabled(t *testing.T) {
	rec := &cmdRecorder{}
	f := upnpHookFirewall(t, rec)
	b := NewBlockerWithUPnP(f, testLogger(), false, FullBanConfig{}, UPnPConfig{Targets: []string{"aa:bb:cc:dd:ee:ff"}})
	b.Close()
	if n := rec.countContains("upnpban"); n != 0 {
		t.Fatalf("未启用 UPnP 拦截时不应下发命令，got %v", rec.snapshot())
	}
}
