package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"pcdn-detect/internal/config"
)

// cliOptions 是命令行解析的结果。cfg 为 nil 表示本次运行已处理完毕
// （-v 输出版本、-T 校验通过等），调用方应直接返回。
type cliOptions struct {
	cfg               *config.Config
	res               *config.Result
	overrides         cliOverrides
	explicitConfig    string
	hasExplicitConfig bool
}

// parseCLI 预扫描特殊参数、加载配置文件并解析全部命令行选项。
// 用法错误 / 配置加载失败会直接打印并退出，与历史行为一致。
func parseCLI(args []string) *cliOptions {
	// 预扫描 -v/--version：只输出版本，不加载配置，避免查询版本时创建默认配置文件。
	if versionRequested(args) {
		fmt.Println(versionString())
		return nil
	}

	// 预扫描 -f/--config：它决定从哪个文件读取配置，必须在加载配置前拿到。
	explicitConfig, hasExplicitConfig := extractConfigFlag(args)
	// 预扫描 -T/--test-config：只校验配置，因此加载阶段不得创建默认配置文件。
	checkConfigOnly := testConfigRequested(args)

	// 加载配置文件（仅查看帮助时跳过，避免产生副作用）。命令行参数优先于配置文件。
	cfg := config.DefaultConfig()
	var cfgRes *config.Result
	if !helpRequested(args) {
		load := config.LoadConfigFor
		if checkConfigOnly {
			load = config.LoadConfigStrict
		}
		res, err := load(explicitConfig, hasExplicitConfig)
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
		maxPorts      int
		protocol      string
		configFlag    string // 已在上面预扫描，此处注册仅为让 -c/--config 能被正常解析
		checkConfig   bool   // 已在上面预扫描，此处注册仅为让 -T/--test-config 能被正常解析
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
	addIntVar(&maxPorts, cfg.MaxPortsValue(), "max-ports")
	addStringVar(&protocol, cfg.Capture.CaptureProto(), "P", "protocol")
	addStringVar(&configFlag, "", "c", "config")
	addBoolVar(&checkConfig, false, "T", "test-config")

	flag.Usage = func() { printUsage(os.Stderr, cfg) }
	flag.Parse()

	// 记录 --peer-limit 是否被显式指定：未指定时其默认值需按最终阈值动态计算。
	peerLimitSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "peer-limit" {
			peerLimitSet = true
		}
	})

	// 只校验配置时不在这里拦截：缺少网卡 / 非法时长由 validateConfig 统一报告（便于显示配置文件路径）。
	if iface == "" && !checkConfigOnly {
		fmt.Fprintln(os.Stderr, "错误：未指定网卡，请用 -i/--interface 指定，或在配置文件中设置 interface，例如 -i br-lan")
		flag.Usage()
		os.Exit(2)
	}
	if trigger <= 0 && !checkConfigOnly {
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
	// 单设备端口条目上限：0 表示不限制；负数无意义，同样按不限制处理。
	if maxPorts < 0 {
		maxPorts = 0
	}
	if duration <= 0 && !checkConfigOnly {
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
		if checkConfigOnly {
			fmt.Fprintf(os.Stderr, "配置检查失败：%v（-P/--protocol）\n", err)
			os.Exit(1)
		}
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
		maxPorts:      maxPorts,
		protocol:      capProto,
		set:           setFlags,
	}

	// --test-config：只校验「配置文件 + 命令行覆盖」的最终结果，不启动任何组件。
	// 通过退出 0，失败退出 1（用法错误仍为 2）。不创建配置文件，也不执行外部命令。
	if checkConfigOnly && cfgRes != nil {
		for _, w := range cfgRes.Warnings {
			fmt.Fprintf(os.Stderr, "警告：%s\n", w)
		}
		if err := applyCLIOverrides(cfg, &ov); err != nil {
			fmt.Fprintf(os.Stderr, "配置检查失败：%v\n", err)
			os.Exit(1)
		}
		if err := validateConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "配置检查失败：%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("配置检查通过：%s\n", cfgRes.Path)
		return nil
	}

	return &cliOptions{
		cfg:               cfg,
		res:               cfgRes,
		overrides:         ov,
		explicitConfig:    explicitConfig,
		hasExplicitConfig: hasExplicitConfig,
	}
}

// testConfigRequested 判断命令行是否只校验配置文件（-T / --test-config），
// 用于在加载配置前切换为「只读不创建」的加载方式。
func testConfigRequested(args []string) bool {
	for _, a := range args {
		switch a {
		case "-T", "-T=true", "--test-config", "-test-config", "--test-config=true":
			return true
		}
	}
	return false
}

// versionRequested 判断命令行是否只想查看版本（-v / --version），
// 需在加载配置前识别，避免查询版本时产生创建配置文件等副作用。
func versionRequested(args []string) bool {
	for _, a := range args {
		switch a {
		case "-v", "-v=true", "--version", "-version", "--version=true":
			return true
		}
	}
	return false
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
	fmt.Fprintf(w, "      --max-ports <数量>       单设备端口条目上限（默认 %d，0 表示不限制；无短选项）\n", cfg.MaxPortsValue())
	fmt.Fprintf(w, "  -P, --protocol <协议>        抓包协议：udp / tcp / all（默认 %s）\n", cfg.Capture.CaptureProto())
	fmt.Fprintf(w, "  -c, --config <路径>          指定配置文件路径（只读取该文件，不自动创建）\n")
	fmt.Fprintf(w, "  -T, --test-config            仅校验配置文件与命令行参数，通过后退出（不启动、不创建文件）\n")
	fmt.Fprintf(w, "  -v, --version                显示版本信息（%s）\n", versionString())
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
	maxPorts      int
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
	if ov.has("max-ports") {
		n := ov.maxPorts
		cfg.Memory.MaxPorts = &n
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
