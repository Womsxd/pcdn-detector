package config

import (
	"fmt"
	"os"
	"testing"
	"time"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/logx"
)

// chdirTemp 切换到临时目录，测试结束后自动切回。
func chdirTemp(t *testing.T) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败：%v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("切换临时目录失败：%v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

// 无任何配置文件时应创建默认配置 pcdn-detect.toml。
func TestConfigCreatedWhenMissing(t *testing.T) {
	chdirTemp(t)

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if !res.Created {
		t.Fatalf("应标记为新建默认配置")
	}
	if res.Path != "pcdn-detect.toml" {
		t.Fatalf("默认配置文件名应为 pcdn-detect.toml，got %s", res.Path)
	}
	if _, err := os.Stat("pcdn-detect.toml"); err != nil {
		t.Fatalf("默认配置文件应已创建：%v", err)
	}
	if res.Config.Detect.Threshold != defaultThreshold {
		t.Fatalf("阈值默认值应为 %d，got %d", defaultThreshold, res.Config.Detect.Threshold)
	}
	if time.Duration(res.Config.Detect.Window) != defaultWindow {
		t.Fatalf("窗口默认值应为 %s，got %s", defaultWindow, time.Duration(res.Config.Detect.Window))
	}
	if res.Config.Capture.Promisc == nil || !*res.Config.Capture.Promisc {
		t.Fatalf("混杂模式默认应为 true")
	}
}

// [firewall] hook 字段应被正确解析（nftables 钩子）。
func TestConfigFirewallHook(t *testing.T) {
	cfg, err := parseConfig([]byte("[firewall]\nbackend = \"nftables\"\n[firewall.nftables]\nhook = \"input\"\n"))
	if err != nil {
		t.Fatalf("解析配置失败：%v", err)
	}
	if cfg.Firewall.Nftables.Hook != "input" {
		t.Fatalf("hook 应为 input，got %q", cfg.Firewall.Nftables.Hook)
	}
}

// 存在 config.toml 时应优先加载，支持注释、字符串与整数时长。
func TestConfigLoadedFromCandidate(t *testing.T) {
	chdirTemp(t)

	content := "# 这是注释\n" +
		"[detect]\n" +
		"threshold = 33\n" +
		"window = \"2m\"\n" +
		"alert_duration = \"90s\"\n" +
		"interval = \"5s\"\n" +
		"[capture]\n" +
		"interface = \"br-lan\"\n" +
		"promisc = false\n" +
		"[log]\n" +
		"timezone = \"Asia/Shanghai\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if res.Created {
		t.Fatalf("已有配置不应再创建默认文件")
	}
	if res.Path != "config.toml" {
		t.Fatalf("应加载 config.toml，got %s", res.Path)
	}
	if res.Config.Capture.Interface != "br-lan" || res.Config.Detect.Threshold != 33 {
		t.Fatalf("基本字段解析错误：%+v", res.Config)
	}
	if time.Duration(res.Config.Detect.Window) != 2*time.Minute ||
		time.Duration(res.Config.Detect.AlertDuration) != 90*time.Second ||
		time.Duration(res.Config.Detect.Interval) != 5*time.Second {
		t.Fatalf("时长字段解析错误：%+v", res.Config)
	}
	if res.Config.Capture.Promisc == nil || *res.Config.Capture.Promisc {
		t.Fatalf("promisc 应为 false")
	}
	if res.Config.Log.Timezone != "Asia/Shanghai" {
		t.Fatalf("时区解析错误：%s", res.Config.Log.Timezone)
	}
	if _, err := os.Stat("pcdn-detect.toml"); err == nil {
		t.Fatalf("加载成功后不应创建默认配置")
	}
}

// 前一个候选加载失败时应继续往下读，并记录警告。
func TestConfigFallsThroughInvalid(t *testing.T) {
	chdirTemp(t)

	// config.toml 为非法 TOML（类型不符）。
	if err := os.WriteFile("config.toml", []byte("[detect]\nthreshold = \"abc\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("pcdn-detect.toml", []byte("[detect]\nthreshold = 7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if res.Path != "pcdn-detect.toml" {
		t.Fatalf("应回退加载 pcdn-detect.toml，got %s", res.Path)
	}
	if res.Config.Detect.Threshold != 7 {
		t.Fatalf("阈值应来自 pcdn-detect.toml，got %d", res.Config.Detect.Threshold)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("跳过的非法配置应产生警告")
	}
}

// 无法加载且默认文件已存在（无法创建）时应报错。
func TestConfigErrorWhenCannotCreate(t *testing.T) {
	chdirTemp(t)

	// 存在但含未知键，且这是唯一的创建目标，导致无法创建。
	if err := os.WriteFile("pcdn-detect.toml", []byte("bogus = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("无法加载且无法创建时应报错")
	}
}

// 时长字段支持整数秒与字符串两种写法。
func TestConfigDurationForms(t *testing.T) {
	chdirTemp(t)

	content := "[detect]\nwindow = 90\ninterval = \"3s\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if time.Duration(res.Config.Detect.Window) != 90*time.Second {
		t.Fatalf("整数应按秒解析，got %s", time.Duration(res.Config.Detect.Window))
	}
	if time.Duration(res.Config.Detect.Interval) != 3*time.Second {
		t.Fatalf("字符串时长解析错误，got %s", time.Duration(res.Config.Detect.Interval))
	}
}

// 低内存模式配置项应能被解析。
func TestConfigLowMemory(t *testing.T) {
	cfg, err := parseConfig([]byte("[memory]\nlow_memory = true\n"))
	if err != nil {
		t.Fatalf("low_memory 解析失败：%v", err)
	}
	if !cfg.Memory.LowMemory {
		t.Fatalf("low_memory 应为 true")
	}
	// 默认（未配置）时应为 false。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 5\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if cfg.Memory.LowMemory {
		t.Fatalf("未配置 low_memory 时应为 false")
	}
}

// NormalizePeerLimit：0/负数表示不限制；低于阈值时提升为阈值；否则原样。
func TestNormalizePeerLimit(t *testing.T) {
	cases := []struct {
		limit, threshold, want int
	}{
		{0, 20, 0},
		{-5, 20, 0},
		{10, 20, 20},
		{20, 20, 20},
		{100, 20, 100},
	}
	for _, c := range cases {
		if got := NormalizePeerLimit(c.limit, c.threshold); got != c.want {
			t.Errorf("NormalizePeerLimit(%d,%d)=%d，期望 %d", c.limit, c.threshold, got, c.want)
		}
	}
}

// peer_limit 默认取 max(1000, threshold*10)；显式 0 表示不限制；显式值受规范化。
func TestConfigPeerLimit(t *testing.T) {
	// threshold=5 → max(1000, 50) = 1000。
	cfg, err := parseConfig([]byte("[detect]\nthreshold = 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 1000 {
		t.Fatalf("threshold=5 时默认上限应为 1000，got %d", got)
	}

	// threshold=200 → max(1000, 2000) = 2000。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 200\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 2000 {
		t.Fatalf("threshold=200 时默认上限应为 2000，got %d", got)
	}

	// 显式 0 表示不限制。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 200\n[memory]\npeer_limit = 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 0 {
		t.Fatalf("显式 peer_limit = 0 应表示不限制，got %d", got)
	}

	// 显式值小于阈值时提升为阈值。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 200\n[memory]\npeer_limit = 50\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 200 {
		t.Fatalf("peer_limit=50 且 threshold=200 时应提升为 200，got %d", got)
	}

	// 显式值大于默认时被采用。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 20\n[memory]\npeer_limit = 5000\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 5000 {
		t.Fatalf("peer_limit=5000 应被采用，got %d", got)
	}

	// 低内存模式且未显式配置 peer_limit 时，默认收敛为 threshold。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 200\n[memory]\nlow_memory = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 200 {
		t.Fatalf("低内存模式且未配置 peer_limit 时默认上限应为 threshold=200，got %d", got)
	}

	// 低内存模式下显式配置 peer_limit 仍优先。
	cfg, err = parseConfig([]byte("[detect]\nthreshold = 20\n[memory]\nlow_memory = true\npeer_limit = 5000\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.PeerLimitValue(); got != 5000 {
		t.Fatalf("低内存模式下显式 peer_limit=5000 应被采用，got %d", got)
	}
}

// ban_active_alerts：启用 / reload 时补发当前告警封禁，默认关闭。
func TestConfigBanActiveAlerts(t *testing.T) {
	cfg, err := parseConfig([]byte("[firewall]\nban_active_alerts = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Firewall.BanActiveAlerts {
		t.Fatal("ban_active_alerts 应为 true")
	}

	cfg, err = parseConfig([]byte("[firewall]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Firewall.BanActiveAlerts {
		t.Fatal("未配置 ban_active_alerts 时应为 false")
	}
}

// ban_ttl：nftables 封禁元素超时，支持时长字符串；未配置时为 0（不设置）。
func TestConfigNftablesBanTTL(t *testing.T) {
	cfg, err := parseConfig([]byte("[firewall]\nbackend = \"nftables\"\n[firewall.nftables]\nban_ttl = \"30m\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := time.Duration(cfg.Firewall.Nftables.BanTTL); got != 30*time.Minute {
		t.Fatalf("ban_ttl 应为 30m，got %s", got)
	}

	cfg, err = parseConfig([]byte("[firewall]\nbackend = \"nftables\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := time.Duration(cfg.Firewall.Nftables.BanTTL); got != 0 {
		t.Fatalf("未配置 ban_ttl 时应为 0，got %s", got)
	}
}

// max_ports：未配置时默认 512；显式 0 / 负数表示不限制；其余原样。
func TestConfigMaxPorts(t *testing.T) {
	cfg, err := parseConfig([]byte("[memory]\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.MaxPortsValue(); got != 512 {
		t.Fatalf("未配置 max_ports 时默认应为 512，got %d", got)
	}

	cfg, err = parseConfig([]byte("[memory]\nmax_ports = 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.MaxPortsValue(); got != 0 {
		t.Fatalf("显式 max_ports = 0 应表示不限制，got %d", got)
	}

	cfg, err = parseConfig([]byte("[memory]\nmax_ports = 128\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if got := cfg.MaxPortsValue(); got != 128 {
		t.Fatalf("显式 max_ports = 128 应被采用，got %d", got)
	}
}

// EffectivePeerLimit：raw 为 nil 时默认 max(1000, threshold*10)；低内存模式下默认收敛为
// threshold；否则以 raw 为准（显式配置优先）并规范化。
func TestEffectivePeerLimit(t *testing.T) {
	cases := []struct {
		rawPresent bool
		rawVal     int
		threshold  int
		lowMemory  bool
		want       int
	}{
		{false, 0, 20, false, 1000},
		{false, 0, 100, false, 1000},
		{false, 0, 200, false, 2000},
		{true, 0, 20, false, 0},
		{true, 50, 200, false, 200},
		{true, 1000, 20, false, 1000},
		// 低内存模式：未配置时默认收敛为 threshold。
		{false, 0, 20, true, 20},
		{false, 0, 200, true, 200},
		// 低内存模式下显式配置仍优先。
		{true, 5000, 20, true, 5000},
		{true, 0, 20, true, 0},
	}
	for _, c := range cases {
		var raw *int
		if c.rawPresent {
			v := c.rawVal
			raw = &v
		}
		if got := EffectivePeerLimit(raw, c.threshold, c.lowMemory); got != c.want {
			t.Errorf("EffectivePeerLimit(present=%v,val=%d,threshold=%d,low=%v)=%d，期望 %d",
				c.rawPresent, c.rawVal, c.threshold, c.lowMemory, got, c.want)
		}
	}
}

// ParseFullBanMode：off/on/device（大小写不敏感）；非法值报错。
func TestParseFullBanMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", FullBanOff, true},
		{"off", FullBanOff, true},
		{"OFF", FullBanOff, true},
		{"on", FullBanOn, true},
		{"device", FullBanDevice, true},
		{"DEVICE", FullBanDevice, true},
		{"foo", "", false},
	}
	for _, c := range cases {
		got, err := ParseFullBanMode(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("ParseFullBanMode(%q) = (%q,%v)，期望 (%q,nil)", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseFullBanMode(%q) 应报错，got (%q,nil)", c.in, got)
		}
	}
}

// [full_ban] 配置解析：模式、阈值、放行端口（显式配置时以其为准，不叠加内置端口）。
func TestConfigFullBan(t *testing.T) {
	cfg, err := parseConfig([]byte("[full_ban]\nmode = \"device\"\nthreshold = 3\nallow = [53, \"1000-1002\"]\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if cfg.FullBan.FullBanMode() != FullBanDevice {
		t.Fatalf("[full_ban] mode 解析错误：%q", cfg.FullBan.FullBanMode())
	}
	if !cfg.FullBan.FullBanEnabled() {
		t.Fatalf("mode=device 应视为启用")
	}
	if cfg.FullBan.FullBanThresholdValue() != 3 {
		t.Fatalf("阈值解析错误：%d", cfg.FullBan.FullBanThresholdValue())
	}
	ports, err := cfg.FullBanAllow()
	if err != nil {
		t.Fatalf("放行端口解析失败：%v", err)
	}
	// 显式配置时以其为准，不再叠加内置常用端口。
	want := []uint16{53, 1000, 1001, 1002}
	if len(ports) != len(want) {
		t.Fatalf("放行端口 %v，期望 %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("放行端口 %v，期望 %v", ports, want)
		}
	}

	// 未配置 allow（为空）时使用内置常用端口。
	empty, err := parseConfig([]byte("[full_ban]\nmode = \"on\"\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	defPorts, err := empty.FullBanAllow()
	if err != nil {
		t.Fatalf("放行端口解析失败：%v", err)
	}
	defWant := []uint16{53, 67, 68, 123, 546, 547}
	if len(defPorts) != len(defWant) {
		t.Fatalf("空配置应使用内置常用端口 %v，got %v", defWant, defPorts)
	}
	for i := range defWant {
		if defPorts[i] != defWant[i] {
			t.Fatalf("空配置应使用内置常用端口 %v，got %v", defWant, defPorts)
		}
	}

	// 非法模式应报错。
	if _, err := parseConfig([]byte("[full_ban]\nmode = \"foo\"\n")); err == nil {
		t.Fatalf("非法 [full_ban] mode 应报错")
	}
	// 非法放行端口应报错。
	bad, err := parseConfig([]byte("[full_ban]\nmode = \"on\"\nallow = [\"abc\"]\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if _, err := bad.FullBanAllow(); err == nil {
		t.Fatalf("非法 allow 应报错")
	}
}

// [full_ban] 默认值：未配置时模式为 off、阈值为默认值。
func TestConfigFullBanDefaults(t *testing.T) {
	cfg, err := parseConfig([]byte("[firewall]\nenabled = true\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	cfg.applyDefaults()
	if cfg.FullBan.FullBanMode() != FullBanOff {
		t.Fatalf("默认模式应为 off，got %q", cfg.FullBan.FullBanMode())
	}
	if cfg.FullBan.FullBanEnabled() {
		t.Fatalf("默认不应启用 full_ban")
	}
	if cfg.FullBan.FullBanThresholdValue() != defaultFullBanThreshold {
		t.Fatalf("默认阈值应为 %d，got %d", defaultFullBanThreshold, cfg.FullBan.FullBanThresholdValue())
	}
}

// FullBanDevices：收集 filter 名单中标记 full_ban = true 且生效的设备 MAC（小写、去重）。
func TestConfigFullBanDevices(t *testing.T) {
	content := "[filter]\n" +
		"list_mode = \"blacklist\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"AA:BB:CC:DD:EE:FF\"\n" +
		"full_ban = true\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"AA:BB:CC:DD:EE:FF\"\n" +
		"ports = [40000]\n" +
		"full_ban = true\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"22:33:44:55:66:77\"\n" +
		"full_ban = true\n" +
		"enabled = false\n"
	cfg, err := parseConfig([]byte(content))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	devices, err := cfg.FullBanDevices()
	if err != nil {
		t.Fatalf("收集失败：%v", err)
	}
	if len(devices) != 1 || devices[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("应只收集去重且生效的设备，got %v", devices)
	}
}

// 未知配置项应视为解析失败。
func TestConfigUnknownKey(t *testing.T) {
	if _, err := parseConfig([]byte("threshhold = 20\n")); err == nil {
		t.Fatalf("未知配置项应报错")
	}
}

// 自动生成的默认配置模板必须能被完整解析（无未知键），
// 防止顶层键误落在某个表头（如 [capture]）之后而被解析为该表的子键。
func TestDefaultConfigTemplateParses(t *testing.T) {
	cfg, err := parseConfig([]byte(defaultConfigTemplate))
	if err != nil {
		t.Fatalf("默认配置模板应可解析，got %v", err)
	}
	if cfg.Filter.ListMode != filter.ModeWhitelist {
		t.Fatalf("模板中的 list_mode 应默认为白名单，got %q", cfg.Filter.ListMode)
	}
	frame, block, blocks := cfg.Capture.RingParams()
	if frame != defaultFrameSize || block != defaultBlockSize || blocks != defaultNumBlocks {
		t.Fatalf("模板中的 [capture] 应解析为默认缓冲，got frame=%d block=%d blocks=%d", frame, block, blocks)
	}
	if got := cfg.Capture.CaptureProto(); got != ProtoModeUDP {
		t.Fatalf("模板中的 protocol 默认应为 udp，got %q", got)
	}
	if cfg.Capture.Snaplen != defaultSnaplen {
		t.Fatalf("模板中的 snaplen 应为 %d，got %d", defaultSnaplen, cfg.Capture.Snaplen)
	}
}

// protocol 缺省时应为 udp；显式配置 udp/tcp/all 时应被遵循；非法值应报错。
func TestConfigCaptureProtocol(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"[capture]\nprotocol = \"udp\"\n", ProtoModeUDP},
		{"[capture]\nprotocol = \"tcp\"\n", ProtoModeTCP},
		{"[capture]\nprotocol = \"all\"\n", ProtoModeAll},
		{"[capture]\nprotocol = \"ALL\"\n", ProtoModeAll}, // 大小写不敏感
	} {
		cfg, err := parseConfig([]byte(tc.in))
		if err != nil {
			t.Fatalf("解析 %q 失败：%v", tc.in, err)
		}
		cfg.applyDefaults()
		if got := cfg.Capture.CaptureProto(); got != tc.want {
			t.Fatalf("%q 应解析为 %q，got %q", tc.in, tc.want, got)
		}
	}

	// 未配置时应为默认 udp。
	cfg, err := parseConfig([]byte("[capture]\nnum_blocks = 4\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	cfg.applyDefaults()
	if got := cfg.Capture.CaptureProto(); got != ProtoModeUDP {
		t.Fatalf("未配置 protocol 时应默认为 udp，got %q", got)
	}

	// 非法值应报错。
	if _, err := parseConfig([]byte("[capture]\nprotocol = \"icmp\"\n")); err == nil {
		t.Fatal("非法 protocol 应报错")
	}
}

// 显式指定配置文件时只使用该文件（优先于默认候选）。
func TestLoadConfigExplicitPath(t *testing.T) {
	chdirTemp(t)
	if err := os.WriteFile("custom.toml", []byte("[detect]\nthreshold = 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("config.toml", []byte("[detect]\nthreshold = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfigFor("custom.toml", true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if res.Path != "custom.toml" || res.Config.Detect.Threshold != 42 {
		t.Fatalf("应使用显式指定的文件，got path=%s threshold=%d", res.Path, res.Config.Detect.Threshold)
	}
}

// 显式指定的文件不存在时应报错，且不创建该文件。
func TestLoadConfigExplicitMissingErrors(t *testing.T) {
	chdirTemp(t)

	res, err := LoadConfigFor("my.toml", true)
	if err == nil {
		t.Fatalf("指定文件不存在时应报错，got res=%+v", res)
	}
	if _, statErr := os.Stat("my.toml"); statErr == nil {
		t.Fatalf("不应创建指定的文件")
	}
}

// 显式指定的文件非法，或父目录不存在时应报错。
func TestLoadConfigExplicitErrors(t *testing.T) {
	chdirTemp(t)

	if err := os.WriteFile("bad.toml", []byte("oops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFor("bad.toml", true); err == nil {
		t.Fatalf("显式指定且非法时应报错")
	}
	if _, err := LoadConfigFor("nodir/x.toml", true); err == nil {
		t.Fatalf("父目录不存在时应报错")
	}
}

// 黑名单以数组表 [[blacklist]] 配置，list_mode 大小写不敏感。
func TestConfigBlacklistTable(t *testing.T) {
	chdirTemp(t)

	content := "[filter]\n" +
		"list_mode = \"BLACKLIST\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if res.Config.Filter.ListMode != filter.ModeBlacklist {
		t.Fatalf("list_mode 解析错误：%q", res.Config.Filter.ListMode)
	}
	bl, wl, err := res.Config.ListEntries()
	if err != nil {
		t.Fatalf("转换失败：%v", err)
	}
	if len(bl) != 2 || len(wl) != 0 {
		t.Fatalf("黑名单条目数应为 2，got blacklist=%v whitelist=%v", bl, wl)
	}
}

// 白名单以数组表 [[whitelist]] 配置：ports 省略=全部端口，元素可为整数或表达式字符串。
func TestConfigWhitelistTable(t *testing.T) {
	chdirTemp(t)

	content := "[filter]\n" +
		"list_mode = \"whitelist\"\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n" +
		"ports = [40000, 40001]\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"22:33:44:55:66:77\"\n" +
		"ports = [\"40000-40002\"]\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	bl, wl, err := res.Config.ListEntries()
	if err != nil {
		t.Fatalf("转换失败：%v", err)
	}
	f, err := filter.NewDeviceFilter(res.Config.Filter.ListMode, bl, wl)
	if err != nil {
		t.Fatalf("构建过滤器失败：%v", err)
	}

	// aa 全部端口不检测；11 仅 40000/40001；22 为范围 40000-40002。
	if f.Allow("aa:bb:cc:dd:ee:ff", 1) {
		t.Fatalf("省略 ports 的条目应为全部端口不检测")
	}
	if f.Allow("11:22:33:44:55:66", 40001) || !f.Allow("11:22:33:44:55:66", 40002) {
		t.Fatalf("整数端口数组解析错误")
	}
	if f.Allow("22:33:44:55:66:77", 40002) || !f.Allow("22:33:44:55:66:77", 40003) {
		t.Fatalf("字符串端口表达式解析错误")
	}
}

// enabled = false 的条目应被跳过。
func TestConfigListDisabledEntry(t *testing.T) {
	chdirTemp(t)

	content := "[filter]\n" +
		"list_mode = \"whitelist\"\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"enabled = false\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	bl, wl, err := res.Config.ListEntries()
	if err != nil {
		t.Fatalf("转换失败：%v", err)
	}
	if len(bl) != 0 || len(wl) != 1 || wl[0] != "11:22:33:44:55:66" {
		t.Fatalf("enabled=false 条目应被跳过，got blacklist=%v whitelist=%v", bl, wl)
	}
}

// 黑名单带端口应被接受并生成端口表达式；条目缺少 mac 时应被拒绝。
func TestConfigListInvalidEntries(t *testing.T) {
	chdirTemp(t)

	// 黑名单带端口：应被接受，生成 MAC:端口表达式。
	withPorts := "[filter]\n" +
		"list_mode = \"blacklist\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"ports = [40000]\n"
	if err := os.WriteFile("config.toml", []byte(withPorts), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	bl, _, err := res.Config.ListEntries()
	if err != nil {
		t.Fatalf("黑名单带端口应被接受：%v", err)
	}
	if len(bl) != 1 || bl[0] != "aa:bb:cc:dd:ee:ff:40000" {
		t.Fatalf("黑名单端口表达式错误：%v", bl)
	}

	// 缺少 mac 应报错。
	noMac := "[filter]\n" +
		"list_mode = \"blacklist\"\n" +
		"[[filter.blacklist]]\n" +
		"enabled = true\n"
	if err := os.WriteFile("config.toml", []byte(noMac), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if _, _, err := res.Config.ListEntries(); err == nil {
		t.Fatalf("缺少 mac 应报错")
	}
}

// 黑名单条目配置端口时应产生告警提示；未配置端口或非 blacklist 模式时不告警。
func TestConfigBlacklistPortWarnings(t *testing.T) {
	cfg, err := parseConfig([]byte("[filter]\nlist_mode = \"blacklist\"\n[[filter.blacklist]]\nmac = \"aa:bb:cc:dd:ee:ff\"\nports = [40000]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ws := cfg.BlacklistPortWarnings(); len(ws) != 1 {
		t.Fatalf("黑名单配置端口应产生 1 条告警，got %v", ws)
	}

	// 未配置端口：不告警。
	cfg, err = parseConfig([]byte("[filter]\nlist_mode = \"blacklist\"\n[[filter.blacklist]]\nmac = \"aa:bb:cc:dd:ee:ff\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ws := cfg.BlacklistPortWarnings(); len(ws) != 0 {
		t.Fatalf("黑名单未配置端口不应告警，got %v", ws)
	}

	// 白名单模式下黑名单被忽略：不告警。
	cfg, err = parseConfig([]byte("[filter]\nlist_mode = \"whitelist\"\n[[filter.blacklist]]\nmac = \"aa:bb:cc:dd:ee:ff\"\nports = [40000]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ws := cfg.BlacklistPortWarnings(); len(ws) != 0 {
		t.Fatalf("白名单模式下不应产生黑名单端口告警，got %v", ws)
	}
}

// 非法 list_mode 应导致解析失败。
func TestConfigListModeInvalid(t *testing.T) {
	if _, err := parseConfig([]byte("[filter]\nlist_mode = \"foo\"\n")); err == nil {
		t.Fatalf("非法 list_mode 应报错")
	}
}

// ParseByteSize 支持纯字节数与常见二进制单位。
func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"", 0, true},
		{"0", 0, true},
		{"262144", 262144, true},
		{"1K", 1024, true},
		{"16MiB", 16 << 20, true},
		{"24M", 24 << 20, true},
		{"2g", 2 << 30, true},
		{"1.5KiB", 1536, true},
		{"abc", 0, false},
		{"10XiB", 0, false},
		{"-1M", 0, false},
	}
	for _, c := range cases {
		got, err := ParseByteSize(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("ParseByteSize(%q) = (%d,%v)，期望 (%d,nil)", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseByteSize(%q) 应报错，got (%d,nil)", c.in, got)
		}
	}
}

// [memory] gc_percent：未配置时不干预（0, nil）；合法值原样返回；非法值（<=0 或超上限）报错。
func TestConfigGCPercent(t *testing.T) {
	// 未配置：返回 (0, nil)，表示保持运行时默认（含 GOGC 环境变量）。
	cfg, err := parseConfig([]byte("[memory]\nlow_memory = true\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if got, err := cfg.GCPercentValue(); err != nil || got != 0 {
		t.Fatalf("未配置 gc_percent 应返回 (0,nil)，got (%d,%v)", got, err)
	}

	// 合法值原样返回。
	cfg, err = parseConfig([]byte("[memory]\ngc_percent = 30\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if got, err := cfg.GCPercentValue(); err != nil || got != 30 {
		t.Fatalf("gc_percent=30 应返回 (30,nil)，got (%d,%v)", got, err)
	}

	// 边界值 1 与 gcPercentMax 应被接受。
	for _, ok := range []string{"1", "1000"} {
		cfg, err = parseConfig([]byte("[memory]\ngc_percent = " + ok + "\n"))
		if err != nil {
			t.Fatalf("解析 %s 失败：%v", ok, err)
		}
		if _, err := cfg.GCPercentValue(); err != nil {
			t.Fatalf("gc_percent=%s 应被接受，got %v", ok, err)
		}
	}

	// 非法值（0 / -1 会禁用或退化 GC；超上限）应报错。
	for _, bad := range []string{"0", "-1", "1001"} {
		cfg, err = parseConfig([]byte("[memory]\ngc_percent = " + bad + "\n"))
		if err != nil {
			t.Fatalf("解析 %s 失败：%v", bad, err)
		}
		if _, err := cfg.GCPercentValue(); err == nil {
			t.Fatalf("gc_percent=%s 应报错", bad)
		}
	}
}

// ParseUPnPMode：空值 / off / on / device 及大小写不敏感。
func TestParseUPnPMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", UPnPOff, true},
		{"off", UPnPOff, true},
		{"OFF", UPnPOff, true},
		{"on", UPnPOn, true},
		{"device", UPnPDevice, true},
		{"DEVICE", UPnPDevice, true},
		{"foo", "", false},
	}
	for _, c := range cases {
		got, err := ParseUPnPMode(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("ParseUPnPMode(%q) = (%q,%v)，期望 (%q,nil)", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseUPnPMode(%q) 应报错，got (%q,nil)", c.in, got)
		}
	}
}

// [upnp] 配置解析：模式与拦截端口（显式配置时以其为准，不叠加内置端口；空则用内置 [1900,5000]）。
func TestConfigUPnP(t *testing.T) {
	cfg, err := parseConfig([]byte("[upnp]\nmode = \"device\"\nports = [1900, \"5000-5001\"]\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if cfg.UPnP.UPnPMode() != UPnPDevice {
		t.Fatalf("[upnp] mode 解析错误：%q", cfg.UPnP.UPnPMode())
	}
	if !cfg.UPnP.UPnPEnabled() {
		t.Fatalf("mode=device 应视为启用")
	}
	ports, err := cfg.UPnPPorts()
	if err != nil {
		t.Fatalf("端口解析失败：%v", err)
	}
	want := []uint16{1900, 5000, 5001}
	if len(ports) != len(want) {
		t.Fatalf("拦截端口 %v，期望 %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("拦截端口 %v，期望 %v", ports, want)
		}
	}

	// 未配置 ports 时使用内置端口。
	empty, err := parseConfig([]byte("[upnp]\nmode = \"on\"\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	defPorts, err := empty.UPnPPorts()
	if err != nil {
		t.Fatalf("端口解析失败：%v", err)
	}
	defWant := []uint16{1900, 5000}
	if len(defPorts) != len(defWant) || defPorts[0] != defWant[0] || defPorts[1] != defWant[1] {
		t.Fatalf("空配置应使用内置端口 %v，got %v", defWant, defPorts)
	}
	// [firewall.iptables] input_chain / [firewall.nftables] input_hook 原样解析；
	// 留空时的默认值（INPUT / input）由 firewall 层按后端补齐，配置层不做默认化。
	fwCfg, err := parseConfig([]byte("[firewall.iptables]\ninput_chain = \"FORWARD\"\n[firewall.nftables]\ninput_hook = \"prerouting\"\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if got := fwCfg.Firewall.Iptables.InputChain; got != "FORWARD" {
		t.Fatalf("input_chain 应解析为 FORWARD，got %q", got)
	}
	if got := fwCfg.Firewall.Nftables.InputHook; got != "prerouting" {
		t.Fatalf("input_hook 应解析为 prerouting，got %q", got)
	}
	if got := empty.Firewall.Iptables.InputChain; got != "" {
		t.Fatalf("未配置 input_chain 应保持为空，got %q", got)
	}
	if got := empty.Firewall.Nftables.InputHook; got != "" {
		t.Fatalf("未配置 input_hook 应保持为空，got %q", got)
	}

	// 非法模式应报错。
	if _, err := parseConfig([]byte("[upnp]\nmode = \"foo\"\n")); err == nil {
		t.Fatalf("非法 [upnp] mode 应报错")
	}
	// 非法端口应报错。
	bad, err := parseConfig([]byte("[upnp]\nmode = \"on\"\nports = [\"abc\"]\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if _, err := bad.UPnPPorts(); err == nil {
		t.Fatalf("非法 ports 应报错")
	}
}

// [upnp] 默认值：未配置时模式为 off。
func TestConfigUPnPDefaults(t *testing.T) {
	cfg, err := parseConfig([]byte("[firewall]\nenabled = true\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	cfg.applyDefaults()
	if cfg.UPnP.UPnPMode() != UPnPOff {
		t.Fatalf("默认模式应为 off，got %q", cfg.UPnP.UPnPMode())
	}
	if cfg.UPnP.UPnPEnabled() {
		t.Fatalf("默认不应启用 upnp")
	}
}

// UPnPFilterValue：黑名单模式仅拦截名单设备（BlockAll=false）；白名单模式拦截全部并放行名单设备（BlockAll=true）。
func TestConfigUPnPFilter(t *testing.T) {
	entries := "[filter]\n" +
		"list_mode = \"%s\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"AA:BB:CC:DD:EE:FF\"\n" +
		"upnp = true\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n" +
		"[[filter.blacklist]]\n" +
		"mac = \"22:33:44:55:66:77\"\n" +
		"enabled = false\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"33:44:55:66:77:88\"\n" +
		"upnp = true\n" +
		"[[filter.whitelist]]\n" +
		"mac = \"44:55:66:77:88:99\"\n"
	cases := []struct {
		mode     string
		listMode string
		blockAll bool
		wantDevs []string
	}{
		// 黑名单：仅拦截名单设备；on 取全部生效黑名单，device 取标记 upnp = true 者。
		{"on", "blacklist", false, []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}},
		{"device", "blacklist", false, []string{"aa:bb:cc:dd:ee:ff"}},
		// 白名单：拦截全部 + 放行名单设备；on 取全部生效白名单，device 取标记 upnp = true 者。
		{"on", "whitelist", true, []string{"33:44:55:66:77:88", "44:55:66:77:88:99"}},
		{"device", "whitelist", true, []string{"33:44:55:66:77:88"}},
		// list_mode 为空：默认按白名单处理，等同于 whitelist。
		{"on", "", true, []string{"33:44:55:66:77:88", "44:55:66:77:88:99"}},
	}
	for _, c := range cases {
		content := "[upnp]\nmode = \"" + c.mode + "\"\n" + fmt.Sprintf(entries, c.listMode)
		cfg, err := parseConfig([]byte(content))
		if err != nil {
			t.Fatalf("[upnp] mode=%s list_mode=%q 解析失败：%v", c.mode, c.listMode, err)
		}
		f, err := cfg.UPnPFilterValue()
		if err != nil {
			t.Fatalf("收集失败：%v", err)
		}
		if f.BlockAll != c.blockAll {
			t.Fatalf("mode=%s list_mode=%q BlockAll=%v，期望 %v", c.mode, c.listMode, f.BlockAll, c.blockAll)
		}
		if len(f.Devices) != len(c.wantDevs) {
			t.Fatalf("mode=%s list_mode=%q 设备 %v，期望 %v", c.mode, c.listMode, f.Devices, c.wantDevs)
		}
		for i := range c.wantDevs {
			if f.Devices[i] != c.wantDevs[i] {
				t.Fatalf("mode=%s list_mode=%q 设备 %v，期望 %v", c.mode, c.listMode, f.Devices, c.wantDevs)
			}
		}
	}

	// 空白名单（list_mode 留空即白名单）：拦截全部，无放行设备。
	cfg, err := parseConfig([]byte("[upnp]\nmode = \"on\"\n[filter]\nlist_mode = \"whitelist\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f, _ := cfg.UPnPFilterValue(); !f.BlockAll || len(f.Devices) != 0 {
		t.Fatalf("空白名单应拦截全部且无放行设备，got %+v", f)
	}

	// off 模式返回零值。
	cfg, err = parseConfig([]byte("[upnp]\nmode = \"off\"\n[filter]\nlist_mode = \"whitelist\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f, _ := cfg.UPnPFilterValue(); f.BlockAll || len(f.Devices) != 0 {
		t.Fatalf("off 模式应返回零值，got %+v", f)
	}
}

// snaplen：未配置用默认值；过小/过大分别被抬升/压到 frame_size；环形参数非法时按默认 frame 计算。
func TestCaptureSnaplenValue(t *testing.T) {
	valid := func(sn int) CaptureConfig {
		return CaptureConfig{FrameSize: defaultFrameSize, BlockSize: defaultBlockSize, NumBlocks: defaultNumBlocks, Snaplen: sn}
	}
	for _, tc := range []struct{ in, want int }{
		{0, defaultSnaplen},
		{-1, defaultSnaplen},
		{1, minSnaplen},
		{minSnaplen - 1, minSnaplen},
		{minSnaplen, minSnaplen},
		{128, 128},
		{defaultSnaplen, defaultSnaplen},
		{defaultFrameSize, defaultFrameSize},
		{defaultFrameSize * 2, defaultFrameSize},
	} {
		if got := valid(tc.in).SnaplenValue(); got != tc.want {
			t.Errorf("snaplen=%d：got %d，期望 %d", tc.in, got, tc.want)
		}
	}

	// 环形参数非法 -> RingParams 回退默认 frame，snaplen 随之被压到默认 frame。
	bad := CaptureConfig{FrameSize: 100, BlockSize: 100, NumBlocks: 0, Snaplen: 4096}
	if got := bad.SnaplenValue(); got != defaultFrameSize {
		t.Fatalf("非法环形参数下 snaplen 应压到默认 frame=%d，got %d", defaultFrameSize, got)
	}
}

// 配置缺省 snaplen 时，applyDefaults 应填入默认值（而不是保持 0）。
func TestApplyDefaultsSnaplen(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	if cfg.Capture.Snaplen != defaultSnaplen {
		t.Fatalf("缺省 snaplen 应为 %d，got %d", defaultSnaplen, cfg.Capture.Snaplen)
	}
}

// 默认环形缓冲：2048B 帧 × 65536B 块 × 4 块 = 256KiB，且满足内核约束。
func TestDefaultRingParams(t *testing.T) {
	cfg := DefaultConfig()
	frame, block, blocks := cfg.Capture.RingParams()
	if frame != 2048 || block != 65536 || blocks != 4 {
		t.Fatalf("默认缓冲参数不符：frame=%d block=%d blocks=%d", frame, block, blocks)
	}
	if block%pageSize != 0 || block%frame != 0 {
		t.Fatalf("默认缓冲不满足内核约束：block=%d frame=%d page=%d", block, frame, pageSize)
	}
	if total := block * blocks; total != 256<<10 {
		t.Fatalf("默认环形缓冲应为 256KiB，got %d", total)
	}
	if got := cfg.Capture.SnaplenValue(); got != 256 {
		t.Fatalf("默认 snaplen 应为 256，got %d", got)
	}
}

// 日志等级：[log] level 默认 warn，显式配置时按不区分大小写解析，非法值在校验阶段报错。
func TestLogLevel(t *testing.T) {
	if got := DefaultConfig().Log.Level; got != logx.LevelNameWarn {
		t.Fatalf("默认日志等级应为 warn，got %q", got)
	}
	if got := DefaultConfig().Log.LevelValue(); got != logx.LevelWarn {
		t.Fatalf("默认日志等级应为 LevelWarn，got %v", got)
	}

	cfg, err := parseConfig([]byte("[log]\nlevel = \"INFO\"\n"))
	if err != nil {
		t.Fatalf("解析 level 失败：%v", err)
	}
	cfg.applyDefaults()
	if cfg.Log.Level != logx.LevelNameInfo || cfg.Log.LevelValue() != logx.LevelInfo {
		t.Fatalf("level = INFO 应规范化为 info，got %q / %v", cfg.Log.Level, cfg.Log.LevelValue())
	}

	// 未配置时由 applyDefaults 补默认值。
	cfg, err = parseConfig([]byte("[log]\ntimezone = \"\"\n"))
	if err != nil {
		t.Fatalf("解析空 level 失败：%v", err)
	}
	cfg.applyDefaults()
	if cfg.Log.Level != logx.LevelNameWarn {
		t.Fatalf("未配置 level 时应回退 warn，got %q", cfg.Log.Level)
	}
}
