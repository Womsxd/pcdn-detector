package main

import (
	"fmt"
	"math"
	"reflect"
	"runtime/debug"
	"strings"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/httpapi"
	"pcdn-detect/internal/state"
	"pcdn-detect/internal/tz"
)

// reload 重新加载配置并原地应用；仅当某组件原地重建失败时，回退到「保存状态 + 自重启」。
// 作为 httpapi.ReloadFunc 同时服务于 SIGHUP 与 POST /api/v1/reload。
func (a *app) reload() (httpapi.ReloadResult, error) {
	// 串行化：并发的 /reload 会互相覆盖当前配置，并对同一个旧 Blocker 重复 Close。
	a.mu.Lock()
	defer a.mu.Unlock()

	res, err := config.LoadConfigFor(a.explicitConfig, a.hasExplicitConfig)
	if err != nil {
		return httpapi.ReloadResult{}, err
	}
	newCfg := res.Config
	if err := applyCLIOverrides(newCfg, &a.ov); err != nil {
		return httpapi.ReloadResult{}, err
	}
	// 先做纯配置校验：失败就直接拒绝本次重载，运行状态（抓包 / 防火墙 / HTTP）保持原样，
	// 不要等到组件重建失败再回退重启。
	if err := validateConfig(newCfg); err != nil {
		return httpapi.ReloadResult{}, fmt.Errorf("配置校验失败：%w", err)
	}

	// fallback 触发兜底重启：保存当前状态并请求退出，由自重启按新配置继承。
	fallback := func(reason string, cause error) (httpapi.ReloadResult, error) {
		a.logger.Printf("原地重载失败（%s：%v），回退到重启", reason, cause)
		var st state.File
		st.SavedAtUnix = time.Now().Unix()
		if a.det != nil {
			st.AlertSessions = a.det.AlertSessions()
		}
		if a.blk != nil {
			st.Block = a.blk.BlockState()
		}
		if serr := state.Save(newCfg.HTTP.StateFilePath(), &st); serr != nil {
			return httpapi.ReloadResult{}, fmt.Errorf("原地重载失败（%s：%v）且保存状态文件失败：%w", reason, cause, serr)
		}
		a.restartRequested = true
		a.cancel()
		return httpapi.ReloadResult{RestartRequired: []string{reason}, Restarting: true}, nil
	}

	var applied []string

	// 1) 抓包原地重配（网卡/环形缓冲变化时原地重开 socket；协议/snaplen/混杂模式在既有 socket 上改）。
	if !reflect.DeepEqual(a.cfg.Capture, newCfg.Capture) {
		if a.capturer == nil {
			return httpapi.ReloadResult{}, fmt.Errorf("抓包未就绪，无法重载 [capture]")
		}
		if rerr := a.capturer.Reconfigure(newCfg.Capture, *newCfg.Capture.Promisc); rerr != nil {
			return fallback("capture", rerr)
		}
		applied = append(applied, "capture")
		a.logger.Printf("抓包配置已原地更新：网卡=%s，protocol=%q，snaplen=%dB，混杂模式=%v",
			newCfg.Capture.Interface, newCfg.Capture.CaptureProto(), newCfg.Capture.SnaplenValue(), *newCfg.Capture.Promisc)
	}

	// 2) 防火墙 / blocker 原地应用：
	//    - 已启用且已有 blocker：Migrate 原地换后端，Blocker 对象、检测层 sink 与 HTTP 指针
	//      都不变，迁移期间的事件只排队、不丢失；
	//    - 从关闭到启用：新建 blocker 并绑定 sink 与 HTTP；
	//    - 从启用到关闭：先摘掉 sink 再 Close，避免事件投递给已关闭对象。
	fwChanged := firewallNeedsRebuild(a.cfg, newCfg)
	if fwChanged {
		// UPnP 过滤方式要在任何破坏性操作之前解析：失败时旧防火墙仍保持原样。
		var upFilter config.UPnPFilter
		if newCfg.Firewall.Enabled {
			var uerr error
			upFilter, uerr = newCfg.UPnPFilterValue()
			if uerr != nil {
				return fallback("firewall", uerr)
			}
		}

		switch {
		case newCfg.Firewall.Enabled && a.blk != nil:
			// build 在旧规则清理之后、新后端落地时调用，返回新 fw 及配套封禁配置。
			build := func() (*firewall.Firewall, blocker.FullBanConfig, blocker.UPnPConfig, error) {
				nfw, ferr := firewall.NewFirewall(newCfg.Firewall, newCfg.FullBan, newCfg.UPnP,
					upFilter, newCfg.Capture.CaptureProto(), a.logger)
				if ferr != nil {
					return nil, blocker.FullBanConfig{}, blocker.UPnPConfig{}, ferr
				}
				fb, ferr := buildFullBan(newCfg, nfw)
				if ferr != nil {
					nfw.Cleanup()
					return nil, blocker.FullBanConfig{}, blocker.UPnPConfig{}, ferr
				}
				return nfw, fb, buildUPnP(newCfg, nfw, upFilter), nil
			}
			nfw, merr := a.blk.Migrate(build)
			if merr != nil {
				return fallback("firewall", merr)
			}
			a.fw = nfw
			if newCfg.Firewall.BanActiveAlerts {
				// 幂等：已存在的封禁会被跳过；用于开启该选项后立即覆盖既有告警。
				a.blk.AdoptSessions(a.det.AlertSessions())
			}
			a.logger.Printf("防火墙已原地切换：%s", nfw.Describe())

		case newCfg.Firewall.Enabled:
			nfw, ferr := firewall.NewFirewall(newCfg.Firewall, newCfg.FullBan, newCfg.UPnP,
				upFilter, newCfg.Capture.CaptureProto(), a.logger)
			if ferr != nil {
				return fallback("firewall", ferr)
			}
			fb, ferr := buildFullBan(newCfg, nfw)
			if ferr != nil {
				nfw.Cleanup()
				return fallback("firewall", ferr)
			}
			nblk := blocker.NewBlockerWithUPnP(nfw, a.logger, newCfg.Log.HideAddress, fb, buildUPnP(newCfg, nfw, upFilter))
			a.fw, a.blk = nfw, nblk
			a.det.SetSink(nblk)
			if a.api != nil {
				a.api.SetBlocker(nblk)
			}
			if newCfg.Firewall.BanActiveAlerts {
				// 先换 sink 再补发：补发期间新出现的告警仍能正常投递到新 blocker。
				nblk.AdoptSessions(a.det.AlertSessions())
			}
			a.logger.Printf("已启用防火墙对接：%s", nfw.Describe())

		default:
			// 先摘 sink / HTTP 指针，再停止旧 blocker，期间到达的事件直接忽略（防火墙已关闭）。
			a.det.SetSink(nil)
			if a.api != nil {
				a.api.SetBlocker(nil)
			}
			if a.blk != nil {
				a.blk.Close()
			}
			if a.fw != nil {
				a.fw.Cleanup()
			}
			a.fw, a.blk = nil, nil
			a.logger.Printf("防火墙已关闭")
		}
		applied = append(applied, "firewall")
	}

	// 3) HTTP 监听原地重启（仅 enabled / listen 变化时）。
	if a.cfg.HTTP.Enabled != newCfg.HTTP.Enabled || a.cfg.HTTP.Listen != newCfg.HTTP.Listen {
		a.stopHTTP()
		if newCfg.HTTP.Enabled {
			if herr := a.startHTTP(newCfg.HTTP); herr != nil {
				return httpapi.ReloadResult{Applied: applied}, fmt.Errorf("重启 HTTP 监听失败：%w", herr)
			}
		} else {
			a.logger.Printf("HTTP API 已关闭")
		}
		applied = append(applied, "http")
	}

	// 4) 无失败风险的热标量。
	if a.cfg.Memory.Limit != newCfg.Memory.Limit {
		if newCfg.Memory.Limit == "" {
			debug.SetMemoryLimit(math.MaxInt64)
			a.memLimit = math.MaxInt64
			applied = append(applied, "memory_limit")
		} else if limit, perr := config.ParseByteSize(newCfg.Memory.Limit); perr != nil {
			a.logger.Printf("警告：memory_limit 无效，已忽略：%v", perr)
		} else if limit > 0 {
			debug.SetMemoryLimit(limit)
			a.memLimit = limit
			applied = append(applied, "memory_limit")
		}
	}
	if !intPtrEq(a.cfg.Memory.GCPercent, newCfg.Memory.GCPercent) {
		if pct, perr := newCfg.GCPercentValue(); perr != nil {
			a.logger.Printf("警告：gc_percent 无效，已忽略：%v", perr)
		} else if pct > 0 {
			debug.SetGCPercent(pct)
			a.gcPercent = pct
			applied = append(applied, "gc_percent")
		}
	}
	// 同步 /dev/memory 展示的运行时参数（HTTP 监听可能在本次 reload 中刚被重启）。
	if a.api != nil {
		a.api.SetRuntimeLimits(a.gcPercent, a.memLimit)
	}
	if !reflect.DeepEqual(a.cfg.Detect, newCfg.Detect) {
		a.det.SetParams(newCfg.Detect.Threshold, time.Duration(newCfg.Detect.Window), time.Duration(newCfg.Detect.AlertDuration))
		a.setInterval(time.Duration(newCfg.Detect.Interval))
		applied = append(applied, "detect")
	}
	if a.cfg.Memory.LowMemory != newCfg.Memory.LowMemory {
		a.det.SetLowMemory(newCfg.Memory.LowMemory)
		applied = append(applied, "memory.low_memory")
	}
	if next, changed := nextPeerLimit(a.peerLimit, newCfg); changed {
		a.det.SetPeerLimit(next)
		a.peerLimit = next
		applied = append(applied, "memory.peer_limit")
	}
	if !intPtrEq(a.cfg.Memory.MaxPorts, newCfg.Memory.MaxPorts) {
		a.det.SetMaxPorts(newCfg.MaxPortsValue())
		applied = append(applied, "memory.max_ports")
	}
	if a.cfg.Log.Timezone != newCfg.Log.Timezone {
		rl, src := tz.ResolveLocation(newCfg.Log.Timezone)
		time.Local = rl
		a.logger.Printf("日志时区已更新：%s（来源：%s）", rl.String(), src)
		applied = append(applied, "log.timezone")
	}
	if a.cfg.Log.HideAddress != newCfg.Log.HideAddress {
		a.det.SetHide(newCfg.Log.HideAddress)
		if a.blk != nil {
			a.blk.SetHide(newCfg.Log.HideAddress)
		}
		applied = append(applied, "log.hide_address")
	}
	if !reflect.DeepEqual(a.cfg.Filter, newCfg.Filter) {
		bl, wl, ferr := newCfg.ListEntries()
		if ferr != nil {
			a.logger.Printf("警告：名单配置错误，已保持原名单：%v", ferr)
		} else if nf, ferr := filter.NewDeviceFilter(newCfg.Filter.ListMode, bl, wl); ferr != nil {
			a.logger.Printf("警告：名单配置错误，已保持原名单：%v", ferr)
		} else {
			a.det.SetFilter(nf)
			a.logger.Printf("名单已热更新：%s", nf.Describe())
			applied = append(applied, "filter")
		}
	}
	if a.api != nil {
		if a.cfg.HTTP.Token != newCfg.HTTP.Token {
			a.api.SetToken(newCfg.HTTP.BearerToken())
			applied = append(applied, "http.token")
		}
		if !intPtrEq(a.cfg.HTTP.DeviceIPLimit, newCfg.HTTP.DeviceIPLimit) {
			a.api.SetDeviceIPLimit(newCfg.HTTP.DeviceIPLimitValue())
			applied = append(applied, "http.device_ip_limit")
		}
	}

	a.cfg = newCfg
	a.logger.Printf("配置已原地重载：%s", joinOrNone(applied))
	return httpapi.ReloadResult{Applied: applied}, nil
}

// joinOrNone 把变更项列表渲染为日志可读文本。
func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "无"
	}
	return strings.Join(items, ", ")
}
