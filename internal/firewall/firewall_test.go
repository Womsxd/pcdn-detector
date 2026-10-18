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

// has 判断是否执行过完全匹配的命令（用于区分 PCDN_DETECT 与 PCDN_DETECT_UPNP 这类前缀相同的链名）。
func (r *cmdRecorder) has(exact string) bool {
	for _, c := range r.snapshot() {
		if c == exact {
			return true
		}
	}
	return false
}

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func boolPtr(v bool) *bool { return &v }

// 后端专用行为见 hook_test.go / iptables_test.go / nftables_test.go；本文件放核心装配与清理用例。

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

// 启动时先清理上一次运行可能残留的 nftables 表，退出时（Cleanup）再删一次。
func TestFirewallCleanupNftables(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{Backend: "nftables"}, config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	const del = "nft delete table bridge pcdn_detect"
	if n := rec.countContains(del); n != 1 {
		t.Fatalf("启动时应先清理残留表，got %d 次：%v", n, rec.snapshot())
	}
	f.Cleanup()
	if n := rec.countContains(del); n != 2 {
		t.Fatalf("退出时应再删除 nftables 表，got %d 次：%v", n, rec.snapshot())
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
