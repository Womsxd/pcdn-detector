package main

import (
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/firewall"
)

// validateConfig 对最终生效配置（配置文件 + 命令行覆盖）做纯校验，不触碰任何运行状态。
// --test-config 与 reload 共用：reload 在应用改动之前调用，校验失败则拒绝重载并继续用旧配置运行。
func validateConfig(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.Firewall.Enabled {
		if err := firewall.ValidateConfig(cfg.Firewall, cfg.FullBan, cfg.UPnP); err != nil {
			return err
		}
	}
	return nil
}
