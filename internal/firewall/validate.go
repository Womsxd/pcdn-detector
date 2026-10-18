package firewall

import (
	"fmt"
	"strings"

	"pcdn-detect/internal/config"
)

// ValidateConfig 对 [firewall] / [full_ban] / [upnp] 做纯配置校验：不执行命令，也不访问系统。
// 与 NewFirewall 的校验保持一致，供 reload 预检与 --test-config 使用：在改动任何运行状态
// （重建防火墙、重启 HTTP 监听）之前就拒绝非法配置，避免重载到一半失败后回退重启。
func ValidateConfig(cfg config.FirewallConfig, fb config.FullBanConfig, up config.UPnPConfig) error {
	switch backend := strings.ToLower(strings.TrimSpace(cfg.Backend)); backend {
	case fwBackendHook:
		if strings.TrimSpace(cfg.Hook.Cmd) == "" {
			return fmt.Errorf("backend = \"hook\" 需要配置 [firewall.hook] 的 cmd")
		}
		if fb.FullBanEnabled() && strings.TrimSpace(fb.Hook.Cmd) == "" {
			return fmt.Errorf("backend = \"hook\" 启用 full_ban 时需要配置 [full_ban.hook] 的 cmd")
		}
		if up.UPnPEnabled() && strings.TrimSpace(up.Hook.Cmd) == "" {
			return fmt.Errorf("backend = \"hook\" 启用 upnp 时需要配置 [upnp.hook] 的 cmd")
		}
	case fwBackendIptables:
		// 与 newFirewallFull 相同的链名兜底与校验：专用链不能与跳转链或彼此重名。
		hook := strings.TrimSpace(cfg.Iptables.Chain)
		if hook == "" {
			hook = defaultChain
		}
		ban := strings.TrimSpace(cfg.Iptables.BanChain)
		if ban == "" {
			ban = defaultIptablesBanChain
		}
		upnp := strings.TrimSpace(cfg.Iptables.UPnPChain)
		if upnp == "" {
			upnp = defaultIptablesUPnPChain
		}
		if err := validateIptablesChains(hook, resolveInputChain(cfg.Iptables.InputChain), ban, upnp); err != nil {
			return err
		}
	case fwBackendNftables:
		if _, err := normalizeNftHook(cfg.Nftables.Hook, nftHookPrerouting); err != nil {
			return err
		}
		if up.UPnPEnabled() {
			if _, err := normalizeNftHook(cfg.Nftables.InputHook, nftHookInput); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("firewall.backend 无效 %q（可选 hook / iptables / nftables）", cfg.Backend)
	}

	if fb.FullBanEnabled() {
		if _, err := config.FullBanAllowPorts(fb.Allow); err != nil {
			return err
		}
	}
	if up.UPnPEnabled() {
		if _, err := config.ParseUPnPPorts(up.Ports); err != nil {
			return err
		}
	}
	return nil
}
