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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {ip} {port} {family}", UnbanCmd: "unban {mac} {ip} {port} {family}"},
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port} {family}", UnbanCmd: "unban {mac} {port} {family}"},
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port} {family} {proto}", UnbanCmd: "unban {mac} {port} {family} {proto}"},
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

// 全端口封禁（hook）：[full_ban] 的 ban_cmd / unban_cmd 支持 {mac} 与 {ports} 占位符，仅执行一次。
func TestFirewallHookFullBan(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{BanCmd: "fullban {mac} {ports}", UnbanCmd: "fullunban {mac}"},
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
		Backend: "hook",
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{Mode: "on"}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err == nil {
		t.Fatalf("hook 后端启用 full_ban 但缺少命令应报错")
	}
}

// [full_ban] allow 支持端口表达式：显式配置时以其为准（不叠加内置端口），去重后升序。
func TestFirewallFullBanAllowExpression(t *testing.T) {
	f, err := newFirewall(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{
		Mode:  "on",
		Allow: []any{int64(53), "1000-1002"},
		Hook:  config.FullBanHookConfig{BanCmd: "fullban {ports}", UnbanCmd: "fullunban {mac}"},
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
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{
		Mode: "on",
		Hook: config.FullBanHookConfig{BanCmd: "fullban {ports}", UnbanCmd: "fullunban {mac}"},
	}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if got := portsCSV(def.FullBanAllowPorts()); got != "53,67,68,123,546,547" {
		t.Fatalf("未配置时应使用内置常用端口，got %q", got)
	}
}

// UPnP 拦截（hook）：[upnp] 的 ban_cmd / unban_cmd 支持 {mac} 与 {ports} 占位符，仅执行一次。
func TestFirewallHookUPnP(t *testing.T) {
	rec := &cmdRecorder{}
	f, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{
		Mode: "on",
		Hook: config.UPnPHookConfig{BanCmd: "upnpban {mac} {ports}", UnbanCmd: "upnpunban {mac}"},
	}, config.ProtoModeUDP, testLogger(), rec.run)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	if !f.UPnPEnabled() {
		t.Fatalf("[upnp] mode=on 时应启用 UPnP 拦截")
	}
	if err := f.UPnPBan("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("UPnP 拦截失败：%v", err)
	}
	if err := f.UPnPUnban("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("UPnP 解除失败：%v", err)
	}
	for _, want := range []string{
		"sh -c upnpban aa:bb:cc:dd:ee:ff 1900,5000",
		"sh -c upnpunban aa:bb:cc:dd:ee:ff",
	} {
		if n := rec.countContains(want); n != 1 {
			t.Fatalf("命令 %q 应执行一次，got %d：%v", want, n, rec.snapshot())
		}
	}
}

// hook 后端启用 upnp 时必须配置 [upnp] 的 ban_cmd / unban_cmd。
func TestFirewallHookUPnPRequiresCommands(t *testing.T) {
	_, err := NewFirewallWithRunnerUPnP(config.FirewallConfig{
		Backend: "hook",
		Hook:    config.FirewallHookConfig{BanCmd: "ban {mac} {port}", UnbanCmd: "unban {mac} {port}"},
	}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, config.ProtoModeUDP, testLogger(), (&cmdRecorder{}).run)
	if err == nil {
		t.Fatalf("hook 后端启用 upnp 但缺少命令应报错")
	}
}
