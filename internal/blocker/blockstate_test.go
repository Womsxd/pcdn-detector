package blocker

import (
	"strings"
	"sync"
	"testing"
	"time"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/firewall"
)

// capRunner 记录下发过的防火墙命令，用于断言封禁动作确已发生。
type capRunner struct {
	mu   sync.Mutex
	cmds []string
}

func (c *capRunner) run(name string, args ...string) error {
	c.mu.Lock()
	c.cmds = append(c.cmds, name+" "+strings.Join(args, " "))
	c.mu.Unlock()
	return nil
}

func (c *capRunner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cmds)
}

func newHookFirewall(t *testing.T) (*firewall.Firewall, *capRunner) {
	t.Helper()
	r := &capRunner{}
	f, err := firewall.NewFirewallWithRunner(
		config.FirewallConfig{Enabled: true, Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "hook {action} {mac} {ip} {port} {family} {proto}"}},
		config.FullBanConfig{}, config.ProtoModeUDP, testLogger(), r.run,
	)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	return f, r
}

func waitBans(t *testing.T, b *Blocker, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(b.Snapshot().Bans) < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(b.Snapshot().Bans); got < want {
		t.Fatalf("封禁条目数 %d，期望 %d", got, want)
	}
}

// BlockState/Restore 应可跨实例往返并在新后端重新下发。
func TestBlockStateRestore(t *testing.T) {
	f, _ := newHookFirewall(t)
	b := NewBlocker(f, testLogger(), false)
	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, "udp")
	waitBans(t, b, 1)

	st := b.BlockState()
	if len(st.Bans) != 1 || st.Bans[0].Port != 40000 || !st.Bans[0].Applied {
		t.Fatalf("BlockState 不符：%+v", st)
	}
	b.Close()

	// 用新实例 + 新防火墙还原，应重新下发封禁。
	f2, r2 := newHookFirewall(t)
	b2 := NewBlocker(f2, testLogger(), false)
	defer b2.Close()
	b2.Restore(st)
	if got := len(b2.Snapshot().Bans); got != 1 {
		t.Fatalf("还原后应有 1 条封禁，got %d", got)
	}
	if r2.count() == 0 {
		t.Fatalf("还原后应通过防火墙重新下发封禁命令")
	}
}

// ForceUnban 应移除条目并下发解封。
func TestForceUnban(t *testing.T) {
	f, r := newHookFirewall(t)
	b := NewBlocker(f, testLogger(), false)
	defer b.Close()

	b.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, "udp")
	waitBans(t, b, 1)
	before := r.count()

	n, err := b.ForceUnban("aa:bb:cc:dd:ee:ff", 40000, "udp")
	if err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if n != 1 {
		t.Fatalf("应解封 1 条，got %d", n)
	}
	if got := len(b.Snapshot().Bans); got != 0 {
		t.Fatalf("解封后不应有封禁，got %d", got)
	}
	if r.count() <= before {
		t.Fatalf("解封应下发防火墙命令")
	}

	// 参数校验。
	if _, err := b.ForceUnban("bad-mac", 40000, "udp"); err == nil {
		t.Fatalf("非法 MAC 应报错")
	}
	if _, err := b.ForceUnban("aa:bb:cc:dd:ee:ff", 40000, "sctp"); err == nil {
		t.Fatalf("非法 proto 应报错")
	}
}
