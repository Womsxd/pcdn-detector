package firewall

import (
	"testing"

	"pcdn-detect/internal/config"
)

// 默认 ban_both=true：hook 命令对 v4/v6 各执行一次，可用 {family} 区分。
func TestFirewallHook(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {ip} {port} {family}"},
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
		Backend: "hook",
		BanBoth: boolPtr(false),
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family}"},
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

// 封禁协议随触发协议：hook 的 {proto} 取触发协议，ban_both 下对 v4/v6 各执行一次。
func TestFirewallHookPerProtocol(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port} {family} {proto}"},
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

// 全端口封禁（hook）：[full_ban.hook] 的单条 cmd 用 {action} 区分 ban / unban，
// 对 v4/v6 各执行一次（{family}），并支持 {mac} {ip} {ports}。
func TestFirewallHookFullBan(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{Cmd: "full {action} {mac} {family} {ip} {ports}"},
	}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.FullBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("全端口封禁失败：%v", err)
	}
	if err := f.FullUnban("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("全端口解封失败：%v", err)
	}
	// v4：{ip} 填入；v6：{ip} 为空。各地址族各执行一次。
	for _, want := range []string{
		"sh -c full ban aa:bb:cc:dd:ee:ff v4 192.168.1.5 53,67,68,123,546,547",
		"sh -c full unban aa:bb:cc:dd:ee:ff v4 192.168.1.5 53,67,68,123,546,547",
		"sh -c full ban aa:bb:cc:dd:ee:ff v6",
		"sh -c full unban aa:bb:cc:dd:ee:ff v6",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("命令 %q 应执行一次，got %d：%v", want, n, rec.snapshot())
		}
	}
}

// hook 后端启用 full_ban 时必须配置 [full_ban.hook] 的 cmd。
func TestFirewallHookFullBanRequiresCommands(t *testing.T) {
	_, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{Mode: "on"}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err == nil {
		t.Fatalf("hook 后端启用 full_ban 但缺少命令应报错")
	}
}

// [full_ban] allow 支持端口表达式：显式配置时以其为准（不叠加内置端口），去重后升序。
func TestFirewallFullBanAllowExpression(t *testing.T) {
	f, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{
		Mode:  "on",
		Allow: []any{int64(53), "1000-1002"},
		Hook:  config.FullBanHookConfig{Cmd: "full {action} {ports}"},
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
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{Cmd: "full {action} {ports}"},
	}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if got := portsCSV(def.FullBanAllowPorts()); got != "53,67,68,123,546,547" {
		t.Fatalf("未配置时应使用内置常用端口，got %q", got)
	}
}

// UPnP 拦截（hook）：[upnp.hook] 的单条 cmd 用 {action} 区分 ban / unban，
// 对 v4/v6 各执行一次（{family}），并支持 {mac} {ip} {ports}。
func TestFirewallHookUPnP(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{
		Mode: "on",
		Hook: config.UPnPHookConfig{Cmd: "upnp {action} {mac} {family} {ip} {ports}"},
	}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if !f.UPnPEnabled() {
		t.Fatalf("[upnp] mode=on 时应启用 UPnP 拦截")
	}
	if err := f.UPnPBan("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 拦截失败：%v", err)
	}
	if err := f.UPnPUnban("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("UPnP 解除失败：%v", err)
	}
	for _, want := range []string{
		"sh -c upnp ban aa:bb:cc:dd:ee:ff v4 192.168.1.5 1900,5000",
		"sh -c upnp unban aa:bb:cc:dd:ee:ff v4 192.168.1.5 1900,5000",
		"sh -c upnp ban aa:bb:cc:dd:ee:ff v6",
		"sh -c upnp unban aa:bb:cc:dd:ee:ff v6",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("命令 %q 应执行一次，got %d：%v", want, n, rec.snapshot())
		}
	}
}

// hook 后端启用 upnp 时必须配置 [upnp.hook] 的 cmd。
func TestFirewallHookUPnPRequiresCommands(t *testing.T) {
	_, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.UPnPFilter{}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err == nil {
		t.Fatalf("hook 后端启用 upnp 但缺少命令应报错")
	}
}

// UPnP 拦截（hook，白名单模式）：同一条 cmd 用 {action} 区分 block-all / unblock-all / allow / disallow，
// 对 v4/v6 各执行一次（{family}）。
func TestFirewallHookUPnPBlockAll(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{
		Mode: "on",
		Hook: config.UPnPHookConfig{Cmd: "upnp {action} {mac} {family} {ip} {ports}"},
	}, config.UPnPFilter{BlockAll: true, Devices: []string{"aa:bb:cc:dd:ee:ff"}}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if err := f.UPnPBlockAll(); err != nil {
		t.Fatalf("全量拦截失败：%v", err)
	}
	if err := f.UPnPAllow("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("放行失败：%v", err)
	}
	if err := f.UPnPDisallow("aa:bb:cc:dd:ee:ff", "192.168.1.5"); err != nil {
		t.Fatalf("取消放行失败：%v", err)
	}
	if err := f.UPnPUnblockAll(); err != nil {
		t.Fatalf("解除全量拦截失败：%v", err)
	}
	// 全量拦截 / 解除：{mac}、{ip} 为空，各地址族执行一次；放行 / 取消放行：v4 填入 {ip}。
	for _, want := range []string{
		"sh -c upnp allow aa:bb:cc:dd:ee:ff v4 192.168.1.5 1900,5000",
		"sh -c upnp disallow aa:bb:cc:dd:ee:ff v4 192.168.1.5 1900,5000",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("命令 %q 应执行一次，got %d：%v", want, n, rec.snapshot())
		}
	}
	if n := rec.countContains("sh -c upnp block-all"); n != 2 {
		t.Fatalf("全量拦截应对 v4/v6 各执行一次，got %d：%v", n, rec.snapshot())
	}
	if n := rec.countContains("sh -c upnp unblock-all"); n != 2 {
		t.Fatalf("全量解除应对 v4/v6 各执行一次，got %d：%v", n, rec.snapshot())
	}
}

// hook 后端白名单模式启用 upnp 时缺少 [upnp.hook] cmd 应报错。
func TestFirewallHookUPnPBlockAllRequiresCommands(t *testing.T) {
	_, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{Cmd: "{action} {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.UPnPFilter{BlockAll: true}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err == nil {
		t.Fatalf("白名单模式下缺少 [upnp.hook] cmd 应报错")
	}
}
