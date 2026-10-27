// Command pcdn-detect 在 OpenWrt / Linux 路由器上监听指定网卡，检测 PCDN 行为并可选地对接防火墙。
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pcdn-detect/internal/capture"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/logx"
	"pcdn-detect/internal/tz"
	"pcdn-detect/internal/util"
)

func main() {
	opts := parseCLI(os.Args[1:])
	if opts == nil {
		return
	}
	cfg, cfgRes := opts.cfg, opts.res
	ov := &opts.overrides

	// 让日志时间按系统时区显示（OpenWrt 的时区在 /etc/TZ，Go 默认不读取）。
	loc, tzSource := tz.ResolveLocation(ov.timezone)
	time.Local = loc

	logger := logx.New(os.Stdout, "", log.LstdFlags)
	logger.SetLevel(cfg.Log.LevelValue())
	logger.Infof("日志时区：%s（来源：%s，当前偏移 %s）", loc.String(), tzSource, time.Now().Format("-07:00"))
	logger.Infof("日志等级：%s（可在 [log] level 中调整，或热重载生效）", logger.Level())
	if cfgRes != nil {
		for _, w := range cfgRes.Warnings {
			logger.Warnf("警告：%s", w)
		}
		if cfgRes.Created {
			logger.Infof("未找到可用的配置文件，已创建默认配置：%s", cfgRes.Path)
		} else {
			logger.Infof("已加载配置文件：%s", cfgRes.Path)
		}
	}

	gcPercent, memLimit := setupMemory(cfg, logger)
	devFilter := setupFilter(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fw, blk := initFirewall(cfg, ov.hideAddress, logger)
	det := detector.NewDetector(ov.trigger, ov.duration, ov.alertDuration, devFilter, logger, ov.hideAddress, ov.lowMemory, ov.peerLimit, ov.maxPorts)
	if ov.lowMemory {
		logger.Infof("已启用低内存模式：端口触发告警后清空对端列表且不再记录新对端，仅保留触发状态")
	}
	if ov.peerLimit > 0 {
		logger.Infof("单端口对端记录上限：%d（达到后不再记录该端口的新对端，可配置 peer_limit / --peer-limit，0 表示不限制）", ov.peerLimit)
	} else {
		logger.Infof("单端口对端记录上限：不限制（peer_limit = 0）")
	}
	if ov.maxPorts > 0 {
		logger.Infof("单设备端口条目上限：%d（达到后按「最接近过期 + 同档内对端最少」提前过期 10%% 的端口，可配置 max_ports / --max-ports，0 表示不限制）", ov.maxPorts)
	} else {
		logger.Infof("单设备端口条目上限：不限制（max_ports = 0）")
	}

	a := &app{
		logger:            logger,
		det:               det,
		ctx:               ctx,
		cancel:            cancel,
		explicitConfig:    opts.explicitConfig,
		hasExplicitConfig: opts.hasExplicitConfig,
		ov:                opts.overrides,
		cfg:               cfg,
		fw:                fw,
		blk:               blk,
		peerLimit:         ov.peerLimit,
		gcPercent:         gcPercent,
		memLimit:          memLimit,
		scanInterval:      ov.interval,
	}
	if a.blk != nil {
		if err := a.blk.SetFilter(devFilter); err != nil {
			a.cleanupFirewall()
			logger.Fatalf("同步封禁名单失败：%v", err)
		}
		det.SetSink(a.blk)
	}

	restoreState(cfg, det, a.blk, logger)

	if cfg.HTTP.Enabled {
		if err := a.startHTTP(cfg.HTTP); err != nil {
			a.cleanupFirewall()
			logger.Fatalf("HTTP API 启动失败：%v", err)
		}
	}

	capturer, err := capture.NewCapturer(ov.iface, ov.promisc, cfg.Capture, det)
	if err != nil {
		a.cleanupFirewall()
		logger.Fatalf("初始化抓包失败（网卡 %s）：%v（请确认已以 root 运行且网卡存在）", ov.iface, err)
	}
	a.capturer = capturer
	defer capturer.Close()

	frame, block, blocks := cfg.Capture.RingParams()
	logger.Infof("抓包缓冲：frame=%dB，block=%dB × %d 块 = %s，snaplen=%dB（可在 [capture] 中调整）",
		frame, block, blocks, util.HumanBytes(uint64(block)*uint64(blocks)), cfg.Capture.SnaplenValue())
	proto := cfg.Capture.CaptureProto()
	logger.Infof("内核抓包过滤：放行 %s（protocol = %q，可在 [capture] 中调整）", config.CaptureProtoLabel(proto), proto)

	// 热重载与退出信号分开用两个 channel：避免重复 SIGHUP 占满缓冲后把 SIGTERM 挤掉。
	// hupCh 容量 1 且处理前后各清空一次，重载期间的连续 SIGHUP 会合并为一次。
	hupCh := make(chan os.Signal, 1)
	termCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	signal.Notify(termCh, os.Interrupt, syscall.SIGTERM)
	go handleSignals(hupCh, termCh, a.reload, logger, cancel)

	// 定期扫描滑动窗口并产生告警；扫描间隔可由 reload 动态调整（每轮读取当前值并重置定时器）。
	go func() {
		t := time.NewTimer(a.getInterval())
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				det.Scan(now)
				t.Reset(a.getInterval())
			}
		}
	}()

	logger.Infof("开始监听网卡 %s：触发阈值=%d，时长=%s，持续提示时长=%s，扫描间隔=%s",
		ov.iface, ov.trigger, ov.duration, ov.alertDuration, a.getInterval())
	reloadHint := "SIGHUP（kill -HUP <pid>）"
	if cfg.HTTP.Enabled {
		reloadHint += " 或 POST /api/v1/reload"
	}
	logger.Infof("配置热重载：%s", reloadHint)

	runErr := capturer.Run(ctx)

	// 等待仍在执行的 reload 结束：它会重建防火墙 / blocker 并读写 HTTP 服务，
	// 下面的清理与 restartRequested 判断必须与其互斥（否则可能重复 Close 同一 Blocker）。
	a.mu.Lock()
	defer a.mu.Unlock()

	// 无论是收到退出信号（Ctrl+C / SIGTERM）还是异常结束，都先解封所有条目，
	// 再清除本程序添加的防火墙规则（如 nftables 表），避免规则残留。
	det.Scan(time.Now())
	det.Summary()
	a.cleanupFirewall()

	if runErr != nil && runErr != context.Canceled {
		logger.Fatalf("抓包异常退出：%v", runErr)
	}

	// reload 触发重启：防火墙规则已按旧后端清理，状态文件已保存；用 exec 自重启以继承封禁状态。
	if a.restartRequested {
		logger.Infof("正在重启以应用新配置（继承封禁状态）...")
		exe, exErr := os.Executable()
		if exErr != nil {
			exe = "/proc/self/exe"
		}
		if exErr := syscall.Exec(exe, os.Args, os.Environ()); exErr != nil {
			logger.Errorf("自重启失败：%v（进程退出；若由 procd/systemd 托管将被重新拉起）", exErr)
			os.Exit(0)
		}
		return
	}
	logger.Infof("已退出")
}
