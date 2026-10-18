package firewall

import (
	"strings"
	"testing"

	"pcdn-detect/internal/config"
)

// ValidateConfig 是 reload 预检与 --test-config 共用的纯校验：不执行命令即可发现构建期错误。
func TestValidateConfig(t *testing.T) {
	iptables := config.FirewallConfig{Backend: "iptables"}
	hook := config.FirewallConfig{Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "my-ban {action} {mac}"}}
	nft := config.FirewallConfig{Backend: "nftables"}

	tests := []struct {
		name    string
		cfg     config.FirewallConfig
		fb      config.FullBanConfig
		up      config.UPnPConfig
		wantErr string
	}{
		{"iptables 默认配置", iptables, config.FullBanConfig{}, config.UPnPConfig{}, ""},
		{"hook 默认配置", hook, config.FullBanConfig{}, config.UPnPConfig{}, ""},
		{"nftables 默认配置", nft, config.FullBanConfig{}, config.UPnPConfig{}, ""},
		{"后端非法", config.FirewallConfig{Backend: "iptables2"}, config.FullBanConfig{}, config.UPnPConfig{}, "backend 无效"},
		{"hook 缺少 cmd", config.FirewallConfig{Backend: "hook"}, config.FullBanConfig{}, config.UPnPConfig{}, "[firewall.hook]"},
		{"hook 启用 full_ban 缺少 cmd", hook, config.FullBanConfig{Mode: "on"}, config.UPnPConfig{}, "[full_ban.hook]"},
		{"hook 启用 upnp 缺少 cmd", hook, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, "[upnp.hook]"},
		{"专用链与跳转链重名", config.FirewallConfig{
			Backend:  "iptables",
			Iptables: config.FirewallIptablesConfig{Chain: "PCDN_DETECT"},
		}, config.FullBanConfig{}, config.UPnPConfig{}, "ban_chain"},
		{"专用链非法字符", config.FirewallConfig{
			Backend:  "iptables",
			Iptables: config.FirewallIptablesConfig{BanChain: "bad chain"},
		}, config.FullBanConfig{}, config.UPnPConfig{}, "ban_chain"},
		{"nft hook 非法", config.FirewallConfig{
			Backend:  "nftables",
			Nftables: config.FirewallNftablesConfig{Hook: "prerouting2"},
		}, config.FullBanConfig{}, config.UPnPConfig{}, "nftables hook 无效"},
		{"nft upnp hook 非法", config.FirewallConfig{
			Backend:  "nftables",
			Nftables: config.FirewallNftablesConfig{InputHook: "bad"},
		}, config.FullBanConfig{}, config.UPnPConfig{Mode: "on"}, "nftables hook 无效"},
		{"full_ban allow 端口非法", iptables, config.FullBanConfig{Mode: "on", Allow: []any{"70000"}}, config.UPnPConfig{}, "[full_ban] allow"},
		{"upnp 端口非法", iptables, config.FullBanConfig{}, config.UPnPConfig{Mode: "on", Ports: []any{"x"}}, "[upnp] ports"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(tc.cfg, tc.fb, tc.up)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错，got：%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("应报错且包含 %q，got：%v", tc.wantErr, err)
			}
		})
	}
}
