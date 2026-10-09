// Command pcdn-detect 在 OpenWrt / Linux 路由器上监听指定网卡，检测 PCDN 行为并可选地对接防火墙。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/capture"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/firewall"
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
		configFlag    string // 已在上方预扫描，此处注册仅为让 -c/--config 能被正常解析
	)

	// 每项同时注册短形式（-x）与完整形式（--xxx），二者等价。
	addStringVar(&iface, cfg.Interface, "i", "interface")
	addIntVar(&trigger, cfg.Threshold, "n", "count")
	addDurationVar(&duration, time.Duration(cfg.Window), "t", "window")
	addDurationVar(&alertDuration, time.Duration(cfg.AlertDuration), "a", "alert-duration")
	addBoolVar(&promisc, *cfg.Promisc, "p", "promisc")
	addDurationVar(&interval, time.Duration(cfg.Interval), "s", "interval")
	addStringVar(&tzFlag, cfg.Timezone, "z", "timezone")
	addBoolVar(&hideAddress, cfg.HideAddress, "H", "hide-address")
	addStringVar(&configFlag, "", "c", "config")

	flag.Usage = func() { printUsage(os.Stderr, cfg) }
	flag.Parse()

	if iface == "" {
		fmt.Fprintln(os.Stderr, "错误：未指定网卡，请用 -i/--interface 指定，或在配置文件中设置 interface，例如 -i br-lan")
		flag.Usage()
		os.Exit(2)
	}
	if trigger <= 0 {
		fmt.Fprintln(os.Stderr, "错误：-n/--count 触发次数必须大于 0")
		os.Exit(2)
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
	if cfg.MemoryLimit != "" {
		if limit, err := config.ParseByteSize(cfg.MemoryLimit); err != nil {
			logger.Printf("警告：memory_limit 无效，已忽略：%v", err)
		} else if limit > 0 {
			debug.SetMemoryLimit(limit)
			logger.Printf("已设置 Go 堆内存软上限：%s（memory_limit = %q）", util.HumanBytes(uint64(limit)), cfg.MemoryLimit)
		}
	}

	blacklist, whitelist, err := cfg.ListEntries()
	if err != nil {
		logger.Fatalf("名单配置错误：%v", err)
	}
	devFilter, err := filter.NewDeviceFilter(cfg.ListMode, blacklist, whitelist)
	if err != nil {
		logger.Fatalf("名单配置错误：%v", err)
	}
	if devFilter.Empty() {
		logger.Fatalf("list_mode=blacklist 但未配置 blacklist，将不会检测任何设备，请先补充名单")
	}
	logger.Printf("名单：%s", devFilter.Describe())

	var (
		blk *blocker.Blocker
		fw  *firewall.Firewall
	)
	if cfg.Firewall.Enabled {
		var ferr error
		fw, ferr = firewall.NewFirewall(cfg.Firewall, cfg.Capture.CaptureProto(), logger)
		if ferr != nil {
			logger.Fatalf("防火墙配置错误：%v", ferr)
		}
		blk = blocker.NewBlocker(fw, logger, hideAddress)
		logger.Printf("已启用防火墙对接：%s", fw.Describe())
	}

	det := detector.NewDetector(trigger, duration, alertDuration, devFilter, logger, hideAddress)
	if blk != nil {
		det.SetSink(blk)
	}

	cap, err := capture.NewCapturer(iface, promisc, cfg.Capture, det)
	if err != nil {
		logger.Fatalf("初始化抓包失败（网卡 %s）：%v（请确认已以 root 运行且网卡存在）", iface, err)
	}
	defer cap.Close()

	frame, block, blocks := cfg.Capture.RingParams()
	logger.Printf("抓包缓冲：frame=%dB，block=%dB × %d 块 = %s（可在 [capture] 中调整）",
		frame, block, blocks, util.HumanBytes(uint64(block)*uint64(blocks)))
	proto := cfg.Capture.CaptureProto()
	logger.Printf("内核抓包过滤：放行 %s（protocol = %q，可在 [capture] 中调整）", config.CaptureProtoLabel(proto), proto)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Println("收到退出信号，正在停止...")
		cancel()
	}()

	// 定期扫描滑动窗口并产生告警。
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				det.Scan(now)
			}
		}
	}()

	logger.Printf("开始监听网卡 %s：触发阈值=%d，时长=%s，持续提示时长=%s，扫描间隔=%s",
		iface, trigger, duration, alertDuration, interval)

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
	fmt.Fprintf(w, "用法: %s [选项]\n\n", os.Args[0])
	fmt.Fprintf(w, "选项（短/长形式等价）:\n")
	fmt.Fprintf(w, "  -i, --interface <网卡>       要监听的网卡名称（必填），如 br-lan、br0、eth0\n")
	fmt.Fprintf(w, "  -n, --count <次数>           触发次数：窗口内同一设备同一端口的不同远端公网 IP 数（默认 %d）\n", cfg.Threshold)
	fmt.Fprintf(w, "  -t, --window <时长>          检测时长（滑动窗口，默认 %s）\n", cfg.Window)
	fmt.Fprintf(w, "  -a, --alert-duration <时长>  持续提示时长（默认 %s）\n", cfg.AlertDuration)
	fmt.Fprintf(w, "  -p, --promisc <布尔>         是否开启混杂模式（默认 %s）\n", strconv.FormatBool(*cfg.Promisc))
	fmt.Fprintf(w, "  -s, --interval <时长>        检测扫描间隔（默认 %s）\n", cfg.Interval)
	fmt.Fprintf(w, "  -z, --timezone <时区>        日志时区，IANA 名称或 POSIX 串；默认自动读取\n")
	fmt.Fprintf(w, "  -H, --hide-address <布尔>    隐藏设备自身的 IPv6/公网地址与 MAC（默认 %s）\n", strconv.FormatBool(cfg.HideAddress))
	fmt.Fprintf(w, "  -c, --config <路径>          指定配置文件路径（默认按候选顺序查找）\n")
	fmt.Fprintf(w, "  -h, --help                   显示本帮助\n\n")
	fmt.Fprintf(w, "时长写法：60s、5m、1h，或纯秒数。\n")
	fmt.Fprintf(w, "配置：按顺序查找当前目录下的 config.toml、pcdn-detect.toml（TOML 格式）；\n")
	fmt.Fprintf(w, "      均不存在或加载失败时自动创建 pcdn-detect.toml；命令行参数优先于配置文件。\n\n")
	fmt.Fprintf(w, "示例: %s -i br-lan -c 20 -t 60s\n", os.Args[0])
}
