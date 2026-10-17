// Command pcdn-detect 在 OpenWrt / Linux 路由器上监听指定网卡，检测 PCDN 行为并可选地对接防火墙。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/capture"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/httpapi"
	"pcdn-detect/internal/state"
	"pcdn-detect/internal/tz"
	"pcdn-detect/internal/util"
)

func main() {
	args := os.Args[1:]

	// 预扫描 -f/--config：它决定从哪个文件读取配置，必须在加载配置前拿到。
	explicitConfig, hasExplicitConfig := extractConfigFlag(args)

	// 加载配置文件（仅查看帮助时跳过，避免产生副作用）。命令行参数优先于配置文件。
	cfg := config.DefaultConfig()
	var cfgRes *config.Result
	if !helpRequested(args) {
		res, err := config.LoadConfigFor(explicitConfig, hasExplicitConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误：%v\n", err)
			os.Exit(1)
		}
		cfg, cfgRes = res.Config, res
	}

	var (
		iface         string
		trigger       int
		duration      time.Duration
		alertDuration time.Duration
		promisc       bool
		interval      time.Duration
		tzFlag        string
		hideAddress   bool
		lowMemory     bool
		peerLimit     int
		protocol      string
		configFlag    string // 已在上方预扫描，此处注册仅为让 -c/--config 能被正常解析
	)

	// 每项同时注册短形式（-x）与完整形式（--xxx），二者等价。
	addStringVar(&iface, cfg.Capture.Interface, "i", "interface")
	addIntVar(&trigger, cfg.Detect.Threshold, "n", "count")
	addDurationVar(&duration, time.Duration(cfg.Detect.Window), "t", "window")
	addDurationVar(&alertDuration, time.Duration(cfg.Detect.AlertDuration), "a", "alert-duration")
	addBoolVar(&promisc, *cfg.Capture.Promisc, "p", "promisc")
	addDurationVar(&interval, time.Duration(cfg.Detect.Interval), "s", "interval")
	addStringVar(&tzFlag, cfg.Log.Timezone, "z", "timezone")
	addBoolVar(&hideAddress, cfg.Log.HideAddress, "H", "hide-address")
	addBoolVar(&lowMemory, cfg.Memory.LowMemory, "L", "low-memory")
	addIntVar(&peerLimit, cfg.PeerLimitValue(), "peer-limit")
	addStringVar(&protocol, cfg.Capture.CaptureProto(), "P", "protocol")
	addStringVar(&configFlag, "", "c", "config")

	flag.Usage = func() { printUsage(os.Stderr, cfg) }
	flag.Parse()

	// 记录 --peer-limit 是否被显式指定：未指定时其默认值需按最终阈值动态计算。
	peerLimitSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "peer-limit" {
			peerLimitSet = true
		}
	})

	if iface == "" {
		fmt.Fprintln(os.Stderr, "错误：未指定网卡，请用 -i/--interface 指定，或在配置文件中设置 interface，例如 -i br-lan")
		flag.Usage()
		os.Exit(2)
	}
	if trigger <= 0 {
		fmt.Fprintln(os.Stderr, "错误：-n/--count 触发次数必须大于 0")
		os.Exit(2)
	}
	// 单端口对端记录上限：命令行显式指定时以其为准；否则用配置值（未配置时默认 max(1000, 阈值×10)；
	// 开启低内存模式时默认改为阈值——达阈值即触发并清空对端，无需保留更多）。
	// 统一规范化：低于阈值时提升为阈值，0 表示不限制。
	if peerLimitSet {
		peerLimit = config.NormalizePeerLimit(peerLimit, trigger)
	} else {
		peerLimit = config.EffectivePeerLimit(cfg.Memory.PeerLimit, trigger, lowMemory)
	}
	if duration <= 0 {
		fmt.Fprintln(os.Stderr, "错误：-t/--window 时长必须大于 0")
		os.Exit(2)
	}
	if alertDuration <= 0 {
		alertDuration = 10 * time.Minute
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}

	// 命令行可指定抓包协议（udp / tcp / all），校验后覆盖配置；非法值报错退出。
	capProto, err := config.ParseCaptureProtocol(protocol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v（-P/--protocol）\n", err)
		os.Exit(2)
	}
	cfg.Capture.Protocol = capProto

	// 记录命令行显式覆盖项：重载时需重新套用，保持「命令行 > 配置文件 > 内置默认」的优先级。
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	ov := cliOverrides{
		iface:         iface,
		trigger:       trigger,
		duration:      duration,
		alertDuration: alertDuration,
		promisc:       promisc,
		interval:      interval,
		timezone:      tzFlag,
		hideAddress:   hideAddress,
		lowMemory:     lowMemory,
		peerLimit:     peerLimit,
		protocol:      capProto,
		set:           setFlags,
	}

	// 让日志时间按系统时区显示（OpenWrt 的时区在 /etc/TZ，Go 默认不读取）。
	loc, tzSource := tz.ResolveLocation(tzFlag)
	time.Local = loc

	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("日志时区：%s（来源：%s，当前偏移 %s）", loc.String(), tzSource, time.Now().Format("-07:00"))
	if cfgRes != nil {
		for _, w := range cfgRes.Warnings {
			logger.Printf("警告：%s", w)
		}
		if cfgRes.Created {
			logger.Printf("未找到可用的配置文件，已创建默认配置：%s", cfgRes.Path)
		} else {
			logger.Printf("已加载配置文件：%s", cfgRes.Path)
		}
	}

	// 低内存设备安全阀：为 Go 堆设置软上限，达到后运行时会更积极地回收内存。
	if cfg.Memory.Limit != "" {
		if limit, err := config.ParseByteSize(cfg.Memory.Limit); err != nil {
			logger.Printf("警告：memory_limit 无效，已忽略：%v", err)
		} else if limit > 0 {
			debug.SetMemoryLimit(limit)
			logger.Printf("已设置 Go 堆内存软上限：%s（memory_limit = %q）", util.HumanBytes(uint64(limit)), cfg.Memory.Limit)
		}
	}

	// GC 目标百分比（可选）：低内存设备用较小的值换取更低的常驻堆峰值，代价是 GC 更频繁、CPU 略升。
	// 与 memory_limit 不冲突：堆逼近软上限时由软上限追加收紧，远离上限时由本项决定。
	// 未配置时保持运行时默认（含 GOGC 环境变量），此处直接跳过，不覆盖用户意图。
	if pct, err := cfg.GCPercentValue(); err != nil {
		logger.Printf("警告：gc_percent 无效，已忽略：%v", err)
	} else if pct > 0 {
		prev := debug.SetGCPercent(pct)
		logger.Printf("已设置 GC 目标百分比：gc_percent = %d（此前为 %d；越小越省内存、越费 CPU）", pct, prev)
	}

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
	logger.Printf("名单：%s", devFilter.Describe())
	for _, w := range cfg.BlacklistPortWarnings() {
		logger.Printf("警告：%s", w)
	}

	var (
		blk *blocker.Blocker
		fw  *firewall.Firewall
	)
	if cfg.Firewall.Enabled {
		upFilter, ferr := cfg.UPnPFilterValue()
		if ferr != nil {
			logger.Fatalf("UPnP 拦截配置错误：%v", ferr)
		}
		fw, ferr = firewall.NewFirewall(cfg.Firewall, cfg.FullBan, cfg.UPnP, upFilter, cfg.Capture.CaptureProto(), logger)
		if ferr != nil {
			logger.Fatalf("防火墙配置错误：%v", ferr)
		}
		fb, ferr := buildFullBan(cfg, fw)
		if ferr != nil {
			logger.Fatalf("全端口封禁配置错误：%v", ferr)
		}
		up := buildUPnP(cfg, fw, upFilter)
		blk = blocker.NewBlockerWithUPnP(fw, logger, hideAddress, fb, up)
		logger.Printf("已启用防火墙对接：%s", fw.Describe())
		if fw.FullBanEnabled() {
			logger.Printf("已启用全 UDP 端口封禁：模式=%s，触发阈值=%d 个被封禁端口，放行端口=%s",
				cfg.FullBan.FullBanMode(), cfg.FullBan.FullBanThresholdValue(), portsLabel(fw.FullBanAllowPorts()))
			if cfg.FullBan.FullBanMode() == config.FullBanDevice && len(fb.Devices) == 0 {
				logger.Printf("警告：[full_ban] mode = \"device\" 但 filter 名单中没有任何条目配置 full_ban = true，该模式不会对任何设备生效")
			}
		}
		if fw.UPnPEnabled() {
			scope := "仅拦截名单内设备"
			if upFilter.BlockAll {
				scope = "拦截全部进入路由器的 UPnP，仅放行名单内设备"
			}
			logger.Printf("已启用 UPnP 拦截：模式=%s，范围=%s，拦截目的端口=%s，关联设备=%d 个",
				cfg.UPnP.UPnPMode(), scope, portsLabel(fw.UPnPPorts()), len(up.Targets))
			if cfg.UPnP.UPnPMode() == config.UPnPDevice && len(up.Targets) == 0 {
				logger.Printf("警告：[upnp] mode = \"device\" 但名单中没有任何条目配置 upnp = true，该模式不会对任何设备生效")
			}
		}
	} else {
		if cfg.FullBan.FullBanEnabled() {
			logger.Printf("警告：已配置 [full_ban] mode = %q 但未启用防火墙（[firewall] enabled = true），该模式不会生效", cfg.FullBan.FullBanMode())
		}
		if cfg.UPnP.UPnPEnabled() {
			logger.Printf("警告：已配置 [upnp] mode = %q 但未启用防火墙（[firewall] enabled = true），该模式不会生效", cfg.UPnP.UPnPMode())
		}
	}

	det := detector.NewDetector(trigger, duration, alertDuration, devFilter, logger, hideAddress, lowMemory, peerLimit)
	if lowMemory {
		logger.Printf("已启用低内存模式：端口触发告警后清空对端列表且不再记录新对端，仅保留触发状态")
	}
	if peerLimit > 0 {
		logger.Printf("单端口对端记录上限：%d（达到后不再记录该端口的新对端，可配置 peer_limit / --peer-limit，0 表示不限制）", peerLimit)
	} else {
		logger.Printf("单端口对端记录上限：不限制（peer_limit = 0）")
	}
	if blk != nil {
		det.SetSink(blk)
	}

	// 继承上一次「reload 触发重启」写入的封禁状态：存在则还原并按当前防火墙后端重新下发，随后删除。
	statePath := cfg.HTTP.StateFilePath()
	if st, err := state.Load(statePath); err != nil {
		logger.Printf("警告：状态文件 %s 损坏，已忽略：%v", statePath, err)
		_ = state.Remove(statePath)
	} else if st != nil {
		if det != nil {
			det.RestoreSessions(st.AlertSessions)
		}
		if blk != nil {
			blk.Restore(st.Block)
		}
		_ = state.Remove(statePath)
		logger.Printf("已继承重启前的封禁状态：%d 条端口封禁、%d 台全端口封禁、%d 个告警会话",
			len(st.Block.Bans), len(st.Block.FullBanned), len(st.AlertSessions))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 运行期可变状态（供 reload 原地更新）。
	var (
		cap       *capture.Capturer
		api       *httpapi.Server
		apiCancel context.CancelFunc
	)
	currentCfg := cfg
	restartRequested := false

	// 扫描间隔可被 reload 动态调整。
	var intervalMu sync.Mutex
	scanInterval := interval
	setInterval := func(d time.Duration) {
		if d <= 0 {
			return
		}
		intervalMu.Lock()
		scanInterval = d
		intervalMu.Unlock()
	}
	getInterval := func() time.Duration {
		intervalMu.Lock()
		defer intervalMu.Unlock()
		return scanInterval
	}

	// startHTTP 按配置启动 HTTP 服务（独立子 ctx，便于 reload 时原地重启监听）。
	var reloadFn httpapi.ReloadFunc
	startHTTP := func(hc config.HTTPConfig) error {
		srv, err := httpapi.New(det, blk, hc, reloadFn, logger)
		if err != nil {
			return err
		}
		hcCtx, hcCancel := context.WithCancel(ctx)
		api, apiCancel = srv, hcCancel
		go func() {
			if rerr := srv.Run(hcCtx); rerr != nil {
				logger.Printf("HTTP API 已停止：%v", rerr)
			}
		}()
		authInfo := "无鉴权"
		switch {
		case hc.BearerToken() != "":
			authInfo = "Bearer 鉴权"
		case hc.NoToken():
			authInfo = "无鉴权（token = " + config.TokenAllowNoToken + "）"
		}
		logger.Printf("HTTP API 已启用：http://%s（%s；/devices 每端口对端 IP 上限 %d）",
			hc.ListenAddr(), authInfo, hc.DeviceIPLimitValue())
		return nil
	}
	stopHTTP := func() {
		if apiCancel != nil {
			apiCancel()
			apiCancel = nil
		}
		api = nil
	}

	// reloadFn 重新加载配置并**原地应用**；仅当某组件原地重建失败时，回退到「保存状态 + 自重启」。
	reloadFn = func() (httpapi.ReloadResult, error) {
		res, err := config.LoadConfigFor(explicitConfig, hasExplicitConfig)
		if err != nil {
			return httpapi.ReloadResult{}, err
		}
		newCfg := res.Config
		if err := applyCLIOverrides(newCfg, &ov); err != nil {
			return httpapi.ReloadResult{}, err
		}

		// fallback 触发兜底重启：保存当前状态并请求退出，由自重启按新配置继承。
		fallback := func(reason string, cause error) (httpapi.ReloadResult, error) {
			logger.Printf("原地重载失败（%s：%v），回退到重启", reason, cause)
			var st state.File
			st.SavedAtUnix = time.Now().Unix()
			if det != nil {
				st.AlertSessions = det.AlertSessions()
			}
			if blk != nil {
				st.Block = blk.BlockState()
			}
			if serr := state.Save(newCfg.HTTP.StateFilePath(), &st); serr != nil {
				return httpapi.ReloadResult{}, fmt.Errorf("原地重载失败（%s：%v）且保存状态文件失败：%w", reason, cause, serr)
			}
			restartRequested = true
			cancel()
			return httpapi.ReloadResult{RestartRequired: []string{reason}, Restarting: true}, nil
		}

		var applied []string

		// 1) 抓包原地重配（网卡/环形缓冲变化时原地重开 socket；协议/snaplen/混杂模式在既有 socket 上改）。
		if !reflect.DeepEqual(currentCfg.Capture, newCfg.Capture) {
			if cap == nil {
				return httpapi.ReloadResult{}, fmt.Errorf("抓包未就绪，无法重载 [capture]")
			}
			if rerr := cap.Reconfigure(newCfg.Capture, *newCfg.Capture.Promisc); rerr != nil {
				return fallback("capture", rerr)
			}
			applied = append(applied, "capture")
			logger.Printf("抓包配置已原地更新：网卡=%s，protocol=%q，snaplen=%dB，混杂模式=%v",
				newCfg.Capture.Interface, newCfg.Capture.CaptureProto(), newCfg.Capture.SnaplenValue(), *newCfg.Capture.Promisc)
		}

		// 2) 防火墙 / blocker 原地重建：先按旧后端解封，再按新后端继承当前封禁。
		fwChanged := !reflect.DeepEqual(currentCfg.Firewall, newCfg.Firewall) ||
			!reflect.DeepEqual(currentCfg.FullBan, newCfg.FullBan) ||
			!reflect.DeepEqual(currentCfg.UPnP, newCfg.UPnP)
		if fwChanged {
			var oldState state.BlockState
			if blk != nil {
				oldState = blk.BlockState()
				blk.Close()
			}
			if fw != nil {
				fw.Cleanup()
			}
			fw, blk = nil, nil
			if newCfg.Firewall.Enabled {
				upFilter, uerr := newCfg.UPnPFilterValue()
				if uerr != nil {
					return fallback("firewall", uerr)
				}
				nfw, ferr := firewall.NewFirewall(newCfg.Firewall, newCfg.FullBan, newCfg.UPnP,
					upFilter, newCfg.Capture.CaptureProto(), logger)
				if ferr != nil {
					return fallback("firewall", ferr)
				}
				fb, ferr := buildFullBan(newCfg, nfw)
				if ferr != nil {
					nfw.Cleanup()
					return fallback("firewall", ferr)
				}
				up := buildUPnP(newCfg, nfw, upFilter)
				nblk := blocker.NewBlockerWithUPnP(nfw, logger, newCfg.Log.HideAddress, fb, up)
				nblk.Restore(oldState)
				fw, blk = nfw, nblk
				det.SetSink(nblk)
				logger.Printf("防火墙已原地重建：%s", nfw.Describe())
			} else {
				det.SetSink(nil)
				logger.Printf("防火墙已关闭")
			}
			applied = append(applied, "firewall")
		}

		// 3) HTTP 监听原地重启（仅 enabled / listen 变化时）。
		if currentCfg.HTTP.Enabled != newCfg.HTTP.Enabled || currentCfg.HTTP.Listen != newCfg.HTTP.Listen {
			stopHTTP()
			if newCfg.HTTP.Enabled {
				if herr := startHTTP(newCfg.HTTP); herr != nil {
					return httpapi.ReloadResult{Applied: applied}, fmt.Errorf("重启 HTTP 监听失败：%w", herr)
				}
			} else {
				logger.Printf("HTTP API 已关闭")
			}
			applied = append(applied, "http")
		}

		// 4) 无失败风险的热标量。
		if currentCfg.Memory.Limit != newCfg.Memory.Limit {
			if newCfg.Memory.Limit == "" {
				debug.SetMemoryLimit(math.MaxInt64)
				applied = append(applied, "memory_limit")
			} else if limit, perr := config.ParseByteSize(newCfg.Memory.Limit); perr != nil {
				logger.Printf("警告：memory_limit 无效，已忽略：%v", perr)
			} else if limit > 0 {
				debug.SetMemoryLimit(limit)
				applied = append(applied, "memory_limit")
			}
		}
		if !intPtrEq(currentCfg.Memory.GCPercent, newCfg.Memory.GCPercent) {
			if pct, perr := newCfg.GCPercentValue(); perr != nil {
				logger.Printf("警告：gc_percent 无效，已忽略：%v", perr)
			} else if pct > 0 {
				debug.SetGCPercent(pct)
				applied = append(applied, "gc_percent")
			}
		}
		if !reflect.DeepEqual(currentCfg.Detect, newCfg.Detect) {
			det.SetParams(newCfg.Detect.Threshold, time.Duration(newCfg.Detect.Window), time.Duration(newCfg.Detect.AlertDuration))
			setInterval(time.Duration(newCfg.Detect.Interval))
			applied = append(applied, "detect")
		}
		if currentCfg.Memory.LowMemory != newCfg.Memory.LowMemory {
			det.SetLowMemory(newCfg.Memory.LowMemory)
			applied = append(applied, "memory.low_memory")
		}
		if !intPtrEq(currentCfg.Memory.PeerLimit, newCfg.Memory.PeerLimit) {
			det.SetPeerLimit(newCfg.PeerLimitValue())
			applied = append(applied, "memory.peer_limit")
		}
		if currentCfg.Log.Timezone != newCfg.Log.Timezone {
			rl, src := tz.ResolveLocation(newCfg.Log.Timezone)
			time.Local = rl
			logger.Printf("日志时区已更新：%s（来源：%s）", rl.String(), src)
			applied = append(applied, "log.timezone")
		}
		if currentCfg.Log.HideAddress != newCfg.Log.HideAddress {
			det.SetHide(newCfg.Log.HideAddress)
			if blk != nil {
				blk.SetHide(newCfg.Log.HideAddress)
			}
			applied = append(applied, "log.hide_address")
		}
		if !reflect.DeepEqual(currentCfg.Filter, newCfg.Filter) {
			bl, wl, ferr := newCfg.ListEntries()
			if ferr != nil {
				logger.Printf("警告：名单配置错误，已保持原名单：%v", ferr)
			} else if nf, ferr := filter.NewDeviceFilter(newCfg.Filter.ListMode, bl, wl); ferr != nil {
				logger.Printf("警告：名单配置错误，已保持原名单：%v", ferr)
			} else {
				det.SetFilter(nf)
				logger.Printf("名单已热更新：%s", nf.Describe())
				applied = append(applied, "filter")
			}
		}
		if api != nil {
			if currentCfg.HTTP.Token != newCfg.HTTP.Token {
				api.SetToken(newCfg.HTTP.BearerToken())
				applied = append(applied, "http.token")
			}
			if !intPtrEq(currentCfg.HTTP.DeviceIPLimit, newCfg.HTTP.DeviceIPLimit) {
				api.SetDeviceIPLimit(newCfg.HTTP.DeviceIPLimitValue())
				applied = append(applied, "http.device_ip_limit")
			}
		}

		currentCfg = newCfg
		logger.Printf("配置已原地重载：%s", joinOrNone(applied))
		return httpapi.ReloadResult{Applied: applied}, nil
	}

	if cfg.HTTP.Enabled {
		if err := startHTTP(cfg.HTTP); err != nil {
			logger.Fatalf("HTTP API 启动失败：%v", err)
		}
	}

	cap, err = capture.NewCapturer(iface, promisc, cfg.Capture, det)
	if err != nil {
		logger.Fatalf("初始化抓包失败（网卡 %s）：%v（请确认已以 root 运行且网卡存在）", iface, err)
	}
	defer cap.Close()

	frame, block, blocks := cfg.Capture.RingParams()
	logger.Printf("抓包缓冲：frame=%dB，block=%dB × %d 块 = %s，snaplen=%dB（可在 [capture] 中调整）",
		frame, block, blocks, util.HumanBytes(uint64(block)*uint64(blocks)), cfg.Capture.SnaplenValue())
	proto := cfg.Capture.CaptureProto()
	logger.Printf("内核抓包过滤：放行 %s（protocol = %q，可在 [capture] 中调整）", config.CaptureProtoLabel(proto), proto)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Println("收到退出信号，正在停止...")
		cancel()
	}()

	// 定期扫描滑动窗口并产生告警；扫描间隔可由 reload 动态调整（每轮读取当前值并重置定时器）。
	go func() {
		t := time.NewTimer(getInterval())
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				det.Scan(now)
				t.Reset(getInterval())
			}
		}
	}()

	logger.Printf("开始监听网卡 %s：触发阈值=%d，时长=%s，持续提示时长=%s，扫描间隔=%s",
		iface, trigger, duration, alertDuration, getInterval())

	runErr := cap.Run(ctx)

	// 无论是收到退出信号（Ctrl+C / SIGTERM）还是异常结束，都先解封所有条目，
	// 再清除本程序添加的防火墙规则（如 nftables 表），避免规则残留。
	det.Scan(time.Now())
	det.Summary()
	if blk != nil {
		blk.Close()
	}
	if fw != nil {
		fw.Cleanup()
	}

	if runErr != nil && runErr != context.Canceled {
		logger.Fatalf("抓包异常退出：%v", runErr)
	}

	// reload 触发重启：防火墙规则已按旧后端清理，状态文件已保存；用 exec 自重启以继承封禁状态。
	if restartRequested {
		logger.Println("正在重启以应用新配置（继承封禁状态）...")
		exe, exErr := os.Executable()
		if exErr != nil {
			exe = "/proc/self/exe"
		}
		if exErr := syscall.Exec(exe, os.Args, os.Environ()); exErr != nil {
			logger.Printf("自重启失败：%v（进程退出；若由 procd/systemd 托管将被重新拉起）", exErr)
			os.Exit(0)
		}
		return
	}
	logger.Println("已退出")
}

// helpRequested 判断命令行是否只是想查看帮助，避免加载/创建配置文件。
func helpRequested(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "-help", "--help":
			return true
		}
	}
	return false
}

// extractConfigFlag 从命令行预扫描 -c/--config 指定的配置文件路径。
// 支持 -c path、-c=path、--config path、--config=path 四种写法。
func extractConfigFlag(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, name := range []string{"--config", "-config", "-c"} {
			if v, ok := strings.CutPrefix(a, name+"="); ok {
				return v, true
			}
			if a == name {
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", false // 缺少参数值，交给主解析器报错
			}
		}
	}
	return "", false
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

// portsLabel 把端口列表渲染为逗号分隔字符串，用于启动日志。
func portsLabel(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

// 以下四个函数为同一变量注册短形式（-x）与完整形式（--xxx）。
func addStringVar(p *string, def string, names ...string) {
	for _, n := range names {
		flag.StringVar(p, n, def, "")
	}
}

func addIntVar(p *int, def int, names ...string) {
	for _, n := range names {
		flag.IntVar(p, n, def, "")
	}
}

func addDurationVar(p *time.Duration, def time.Duration, names ...string) {
	for _, n := range names {
		flag.DurationVar(p, n, def, "")
	}
}

func addBoolVar(p *bool, def bool, names ...string) {
	for _, n := range names {
		flag.BoolVar(p, n, def, "")
	}
}

// printUsage 打印帮助；选项默认值取自实际生效的配置（含配置文件）。
func printUsage(w io.Writer, cfg *config.Config) {
	fmt.Fprintf(w, "PCDN 行为检测工具（运行于 OpenWrt / Linux 路由器）\n\n")
	fmt.Fprintf(w, "仓库地址:\n")
	fmt.Fprintf(w, "  https://github.com/Womsxd/pcdn-detector\n")
	fmt.Fprintf(w, "  https://cnb.cool/womsxd/pcdn-detector\n\n")
	fmt.Fprintf(w, "用法: %s [选项]\n\n", os.Args[0])
	fmt.Fprintf(w, "选项（短/长形式等价）:\n")
	fmt.Fprintf(w, "  -i, --interface <网卡>       要监听的网卡名称（必填），如 br-lan、br0、eth0\n")
	fmt.Fprintf(w, "  -n, --count <次数>           触发次数：窗口内同一设备同一端口的不同远端公网 IP 数（默认 %d）\n", cfg.Detect.Threshold)
	fmt.Fprintf(w, "  -t, --window <时长>          检测时长（滑动窗口，默认 %s）\n", cfg.Detect.Window)
	fmt.Fprintf(w, "  -a, --alert-duration <时长>  持续提示时长（默认 %s）\n", cfg.Detect.AlertDuration)
	fmt.Fprintf(w, "  -p, --promisc <布尔>         是否开启混杂模式（默认 %s）\n", strconv.FormatBool(*cfg.Capture.Promisc))
	fmt.Fprintf(w, "  -s, --interval <时长>        检测扫描间隔（默认 %s）\n", cfg.Detect.Interval)
	fmt.Fprintf(w, "  -z, --timezone <时区>        日志时区，IANA 名称或 POSIX 串；默认自动读取\n")
	fmt.Fprintf(w, "  -H, --hide-address <布尔>    隐藏设备自身的 IPv6/公网地址与 MAC（默认 %s）\n", strconv.FormatBool(cfg.Log.HideAddress))
	fmt.Fprintf(w, "  -L, --low-memory <布尔>      低内存模式：触发告警后清空对端列表且不再记录新对端（默认 %s）\n", strconv.FormatBool(cfg.Memory.LowMemory))
	fmt.Fprintf(w, "      --peer-limit <数量>      单端口对端记录上限（默认 %d，0 表示不限制；无短选项）\n", cfg.PeerLimitValue())
	fmt.Fprintf(w, "  -P, --protocol <协议>        抓包协议：udp / tcp / all（默认 %s）\n", cfg.Capture.CaptureProto())
	fmt.Fprintf(w, "  -c, --config <路径>          指定配置文件路径（只读取该文件，不自动创建）\n")
	fmt.Fprintf(w, "  -h, --help                   显示本帮助\n\n")
	fmt.Fprintf(w, "时长写法：60s、5m、1h，或纯秒数。\n")
	fmt.Fprintf(w, "配置：按顺序查找当前目录下的 config.toml、pcdn-detect.toml（TOML 格式）；\n")
	fmt.Fprintf(w, "      均不存在或加载失败时自动创建 pcdn-detect.toml；命令行参数优先于配置文件。\n\n")
	fmt.Fprintf(w, "示例: %s -i br-lan -c 20 -t 60s\n", os.Args[0])
}

// cliOverrides 记录启动时命令行显式指定的值与设置项，供 reload 重新套用（命令行 > 文件）。
type cliOverrides struct {
	iface         string
	trigger       int
	duration      time.Duration
	alertDuration time.Duration
	promisc       bool
	interval      time.Duration
	timezone      string
	hideAddress   bool
	lowMemory     bool
	peerLimit     int
	protocol      string
	set           map[string]bool
}

func (ov *cliOverrides) has(names ...string) bool {
	for _, n := range names {
		if ov.set[n] {
			return true
		}
	}
	return false
}

// applyCLIOverrides 把命令行显式指定项套用到配置上（与启动时的优先级一致）。
func applyCLIOverrides(cfg *config.Config, ov *cliOverrides) error {
	if ov.has("i", "interface") {
		cfg.Capture.Interface = ov.iface
	}
	if ov.has("n", "count") {
		cfg.Detect.Threshold = ov.trigger
	}
	if ov.has("t", "window") {
		cfg.Detect.Window = config.Duration(ov.duration)
	}
	if ov.has("a", "alert-duration") {
		cfg.Detect.AlertDuration = config.Duration(ov.alertDuration)
	}
	if ov.has("p", "promisc") {
		p := ov.promisc
		cfg.Capture.Promisc = &p
	}
	if ov.has("s", "interval") {
		cfg.Detect.Interval = config.Duration(ov.interval)
	}
	if ov.has("z", "timezone") {
		cfg.Log.Timezone = ov.timezone
	}
	if ov.has("H", "hide-address") {
		cfg.Log.HideAddress = ov.hideAddress
	}
	if ov.has("L", "low-memory") {
		cfg.Memory.LowMemory = ov.lowMemory
	}
	if ov.has("peer-limit") {
		n := ov.peerLimit
		cfg.Memory.PeerLimit = &n
	}
	if ov.has("P", "protocol") {
		p, err := config.ParseCaptureProtocol(ov.protocol)
		if err != nil {
			return fmt.Errorf("protocol 无效：%w", err)
		}
		cfg.Capture.Protocol = p
	}
	return nil
}

// intPtrEq 比较两个 *int 是否等价（均为 nil，或指向相等值）。
func intPtrEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "无"
	}
	return strings.Join(items, ", ")
}
