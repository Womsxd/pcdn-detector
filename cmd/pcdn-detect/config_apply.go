package main

import (
	"reflect"
	"strconv"
	"strings"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/firewall"
)

// firewallNeedsRebuild 判断 reload 时是否需要重建防火墙 / blocker：
// [firewall]、[full_ban]、[upnp] 任一段变化，或已启用防火墙时 [capture] protocol 变化。
// protocol 决定封禁协议与 nftables 预建的集合（<set>_<family>_<proto>），只改 protocol
// 而不重建时，新协议的封禁命令会因集合不存在而全部失败（仅记录日志）。
func firewallNeedsRebuild(oldCfg, newCfg *config.Config) bool {
	if !reflect.DeepEqual(oldCfg.Firewall, newCfg.Firewall) ||
		!reflect.DeepEqual(oldCfg.FullBan, newCfg.FullBan) ||
		!reflect.DeepEqual(oldCfg.UPnP, newCfg.UPnP) {
		return true
	}
	// 防火墙未启用时没有集合需要预建，协议变化只需重配抓包。
	return newCfg.Firewall.Enabled && oldCfg.Capture.CaptureProto() != newCfg.Capture.CaptureProto()
}

// nextPeerLimit 返回 reload 后 detector 应生效的单端口对端上限，以及是否需要更新。
// 上限由 threshold / low_memory / peer_limit 共同推导，任一变化都必须重算：否则阈值调高后
// 旧上限（可能小于新阈值）会让端口永远记录不到阈值个对端，告警静默失效。
// cur 为 detector 当前生效值（启动时已按命令行覆盖计算，不能再用当前配置推导）。
func nextPeerLimit(cur int, newCfg *config.Config) (int, bool) {
	next := newCfg.PeerLimitValue()
	return next, next != cur
}

// buildFullBan 依据配置构建全 UDP 端口封禁配置；防火墙未启用全端口封禁时返回 Enabled=false。
func buildFullBan(cfg *config.Config, fw *firewall.Firewall) (blocker.FullBanConfig, error) {
	if !fw.FullBanEnabled() {
		return blocker.FullBanConfig{}, nil
	}
	fb := blocker.FullBanConfig{
		Enabled:   true,
		Mode:      cfg.FullBan.FullBanMode(),
		Threshold: cfg.FullBan.FullBanThresholdValue(),
	}
	if fb.Mode == config.FullBanDevice {
		devices, err := cfg.FullBanDevices()
		if err != nil {
			return blocker.FullBanConfig{}, err
		}
		set := make(map[string]struct{}, len(devices))
		for _, d := range devices {
			set[d] = struct{}{}
		}
		fb.Devices = set
	}
	return fb, nil
}

// buildUPnP 依据配置与解析后的过滤方式构建 UPnP 拦截配置；防火墙未启用 UPnP 拦截时返回 Enabled=false。
func buildUPnP(cfg *config.Config, fw *firewall.Firewall, f config.UPnPFilter) blocker.UPnPConfig {
	if !fw.UPnPEnabled() {
		return blocker.UPnPConfig{}
	}
	return blocker.UPnPConfig{
		Enabled:  true,
		Mode:     cfg.UPnP.UPnPMode(),
		BlockAll: f.BlockAll,
		Targets:  f.Devices,
	}
}

// portsLabel 把端口列表渲染为逗号分隔字符串，用于日志。
func portsLabel(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

// intPtrEq 比较两个 *int 是否等价（均为 nil，或指向相等值）。
func intPtrEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
