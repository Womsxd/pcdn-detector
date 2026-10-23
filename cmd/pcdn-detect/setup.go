package main

import (
	"runtime/debug"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/logx"
	"pcdn-detect/internal/state"
	"pcdn-detect/internal/util"
)

// setupMemory 应用 [memory] 配置（堆软上限 / GC 目标百分比），并返回当前生效值供 /dev/memory 展示。
//
// 记录当前生效的 GC 目标百分比与堆软上限：二者没有 getter，读取它们的 API 会
// stop-the-world 并改写设置（SetMemoryLimit(-1) 会关闭堆软上限），故只在启动与配置变更时读取。
func setupMemory(cfg *config.Config, logger *logx.Logger) (gcPercent int, memLimit int64) {
	gcPercent = debug.SetGCPercent(-1)
	debug.SetGCPercent(gcPercent)
	memLimit = debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(memLimit)

	// 低内存设备安全阀：为 Go 堆设置软上限，达到后运行时会更积极地回收内存。
	if cfg.Memory.Limit != "" {
		if limit, err := config.ParseByteSize(cfg.Memory.Limit); err != nil {
			logger.Warnf("警告：memory_limit 无效，已忽略：%v", err)
		} else if limit > 0 {
			debug.SetMemoryLimit(limit)
			memLimit = limit
			logger.Infof("已设置 Go 堆内存软上限：%s（memory_limit = %q）", util.HumanBytes(uint64(limit)), cfg.Memory.Limit)
		}
	}

	// GC 目标百分比（可选）：低内存设备用较小的值换取更低的常驻堆峰值，代价是 GC 更频繁、CPU 略升。
	// 与 memory_limit 不冲突：堆逼近软上限时由软上限追加收紧，远离上限时由本项决定。
	// 未配置时保持运行时默认（含 GOGC 环境变量），此处直接跳过，不覆盖用户意图。
	if pct, err := cfg.GCPercentValue(); err != nil {
		logger.Warnf("警告：gc_percent 无效，已忽略：%v", err)
	} else if pct > 0 {
		prev := debug.SetGCPercent(pct)
		gcPercent = pct
		logger.Infof("已设置 GC 目标百分比：gc_percent = %d（此前为 %d；越小越省内存、越费 CPU）", pct, prev)
	}
	return gcPercent, memLimit
}

// setupFilter 依据 [filter] 构建设备过滤器；名单配置错误时直接退出（无法安全检测）。
func setupFilter(cfg *config.Config, logger *logx.Logger) *filter.DeviceFilter {
	blacklist, whitelist, err := cfg.ListEntries()
	if err != nil {
		logger.Fatalf("名单配置错误：%v", err)
	}
	devFilter, err := filter.NewDeviceFilter(cfg.Filter.ListMode, blacklist, whitelist)
	if err != nil {
		logger.Fatalf("名单配置错误：%v", err)
	}
	if devFilter.Empty() {
		logger.Fatalf("list_mode=blacklist 但未配置 blacklist，将不会检测任何设备，请先补充名单")
	}
	logger.Infof("名单：%s", devFilter.Describe())
	for _, w := range cfg.BlacklistPortWarnings() {
		logger.Warnf("警告：%s", w)
	}
	return devFilter
}

// initFirewall 依据配置构建防火墙与封禁协调器；[firewall] 未启用时返回 nil。
// hideAddress 为命令行隐私模式（可能与 cfg.Log.HideAddress 不同，故显式传入）。
func initFirewall(cfg *config.Config, hideAddress bool, logger *logx.Logger) (*firewall.Firewall, *blocker.Blocker) {
	if !cfg.Firewall.Enabled {
		if cfg.FullBan.FullBanEnabled() {
			logger.Warnf("警告：已配置 [full_ban] mode = %q 但未启用防火墙（[firewall] enabled = true），该模式不会生效", cfg.FullBan.FullBanMode())
		}
		if cfg.UPnP.UPnPEnabled() {
			logger.Warnf("警告：已配置 [upnp] mode = %q 但未启用防火墙（[firewall] enabled = true），该模式不会生效", cfg.UPnP.UPnPMode())
		}
		return nil, nil
	}

	upFilter, ferr := cfg.UPnPFilterValue()
	if ferr != nil {
		logger.Fatalf("UPnP 拦截配置错误：%v", ferr)
	}
	fw, ferr := firewall.NewFirewall(cfg.Firewall, cfg.FullBan, cfg.UPnP, upFilter, cfg.Capture.CaptureProto(), logger)
	if ferr != nil {
		logger.Fatalf("防火墙配置错误：%v", ferr)
	}
	fb, ferr := buildFullBan(cfg, fw)
	if ferr != nil {
		logger.Fatalf("全端口封禁配置错误：%v", ferr)
	}
	up := buildUPnP(cfg, fw, upFilter)
	blk := blocker.NewBlockerWithUPnP(fw, logger, hideAddress, fb, up)
	logger.Infof("已启用防火墙对接：%s", fw.Describe())
	if fw.FullBanEnabled() {
		logger.Infof("已启用全 UDP 端口封禁：模式=%s，触发阈值=%d 个被封禁端口，放行端口=%s",
			cfg.FullBan.FullBanMode(), cfg.FullBan.FullBanThresholdValue(), portsLabel(fw.FullBanAllowPorts()))
		if cfg.FullBan.FullBanMode() == config.FullBanDevice && len(fb.Devices) == 0 {
			logger.Warnf("警告：[full_ban] mode = \"device\" 但 filter 名单中没有任何条目配置 full_ban = true，该模式不会对任何设备生效")
		}
	}
	if fw.UPnPEnabled() {
		scope := "仅拦截名单内设备"
		if upFilter.BlockAll {
			scope = "拦截全部进入路由器的 UPnP，仅放行名单内设备"
		}
		logger.Infof("已启用 UPnP 拦截：模式=%s，范围=%s，拦截目的端口=%s，关联设备=%d 个",
			cfg.UPnP.UPnPMode(), scope, portsLabel(fw.UPnPPorts()), len(up.Targets))
		if cfg.UPnP.UPnPMode() == config.UPnPDevice && len(up.Targets) == 0 {
			logger.Warnf("警告：[upnp] mode = \"device\" 但名单中没有任何条目配置 upnp = true，该模式不会对任何设备生效")
		}
	}
	return fw, blk
}

// restoreState 继承上一次「reload 触发重启」写入的封禁状态：
// 存在则还原并按当前防火墙后端重新下发，随后删除状态文件。
func restoreState(cfg *config.Config, det *detector.Detector, blk *blocker.Blocker, logger *logx.Logger) {
	statePath := cfg.HTTP.StateFilePath()
	st, err := state.Load(statePath)
	if err != nil {
		logger.Warnf("警告：状态文件 %s 损坏，已忽略：%v", statePath, err)
		_ = state.Remove(statePath)
		return
	}
	if st == nil {
		return
	}
	if det != nil {
		det.RestoreSessions(st.AlertSessions)
	}
	if blk != nil {
		blk.Restore(st.Block)
		// 可选：状态文件只恢复了告警会话（或封禁状态缺失）时，直接按当前告警补发封禁。
		if cfg.Firewall.BanActiveAlerts {
			blk.AdoptSessions(det.AlertSessions())
			logger.Infof("已按当前告警补发封禁（ban_active_alerts = true）")
		}
	}
	_ = state.Remove(statePath)
	logger.Infof("已继承重启前的封禁状态：%d 条端口封禁、%d 台全端口封禁、%d 个告警会话",
		len(st.Block.Bans), len(st.Block.FullBanned), len(st.AlertSessions))
}
