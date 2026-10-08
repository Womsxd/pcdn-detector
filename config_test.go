package main

import (
	"os"
	"testing"
	"time"
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
	if res.Config.Threshold != defaultThreshold {
		t.Fatalf("阈值默认值应为 %d，got %d", defaultThreshold, res.Config.Threshold)
	}
	if time.Duration(res.Config.Window) != defaultWindow {
		t.Fatalf("窗口默认值应为 %s，got %s", defaultWindow, time.Duration(res.Config.Window))
	}
	if res.Config.Promisc == nil || !*res.Config.Promisc {
		t.Fatalf("混杂模式默认应为 true")
	}
}

// 存在 config.toml 时应优先加载，支持注释、字符串与整数时长。
func TestConfigLoadedFromCandidate(t *testing.T) {
	chdirTemp(t)

	content := "# 这是注释\n" +
		"interface = \"br-lan\"\n" +
		"threshold = 33\n" +
		"window = \"2m\"\n" +
		"alert_duration = \"90s\"\n" +
		"promisc = false\n" +
		"interval = \"5s\"\n" +
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
	if res.Config.Interface != "br-lan" || res.Config.Threshold != 33 {
		t.Fatalf("基本字段解析错误：%+v", res.Config)
	}
	if time.Duration(res.Config.Window) != 2*time.Minute ||
		time.Duration(res.Config.AlertDuration) != 90*time.Second ||
		time.Duration(res.Config.Interval) != 5*time.Second {
		t.Fatalf("时长字段解析错误：%+v", res.Config)
	}
	if res.Config.Promisc == nil || *res.Config.Promisc {
		t.Fatalf("promisc 应为 false")
	}
	if res.Config.Timezone != "Asia/Shanghai" {
		t.Fatalf("时区解析错误：%s", res.Config.Timezone)
	}
	if _, err := os.Stat("pcdn-detect.toml"); err == nil {
		t.Fatalf("加载成功后不应创建默认配置")
	}
}

// 前一个候选加载失败时应继续往下读，并记录警告。
func TestConfigFallsThroughInvalid(t *testing.T) {
	chdirTemp(t)

	// config.toml 为非法 TOML（类型不符）。
	if err := os.WriteFile("config.toml", []byte("threshold = \"abc\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("pcdn-detect.toml", []byte("threshold = 7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if res.Path != "pcdn-detect.toml" {
		t.Fatalf("应回退加载 pcdn-detect.toml，got %s", res.Path)
	}
	if res.Config.Threshold != 7 {
		t.Fatalf("阈值应来自 pcdn-detect.toml，got %d", res.Config.Threshold)
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

	content := "window = 90\ninterval = \"3s\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if time.Duration(res.Config.Window) != 90*time.Second {
		t.Fatalf("整数应按秒解析，got %s", time.Duration(res.Config.Window))
	}
	if time.Duration(res.Config.Interval) != 3*time.Second {
		t.Fatalf("字符串时长解析错误，got %s", time.Duration(res.Config.Interval))
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
	if cfg.ListMode != listModeNone {
		t.Fatalf("模板中的 list_mode 应解析为顶层空值，got %q", cfg.ListMode)
	}
	frame, block, blocks := cfg.Capture.ringParams()
	if frame != defaultFrameSize || block != defaultBlockSize || blocks != defaultNumBlocks {
		t.Fatalf("模板中的 [capture] 应解析为默认缓冲，got frame=%d block=%d blocks=%d", frame, block, blocks)
	}
	if !cfg.Capture.udpOnly() {
		t.Fatalf("模板中的 udp_only 默认应为 true")
	}
}

// udp_only 缺省时应为 true；显式配置时应被遵循。
func TestConfigCaptureUDPOnly(t *testing.T) {
	// 显式 false。
	cfg, err := parseConfig([]byte("[capture]\nudp_only = false\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	cfg.applyDefaults()
	if cfg.Capture.udpOnly() {
		t.Fatalf("udp_only = false 应解析为 false")
	}

	// 未配置时应为默认 true。
	cfg2, err := parseConfig([]byte("[capture]\nnum_blocks = 4\n"))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	cfg2.applyDefaults()
	if !cfg2.Capture.udpOnly() {
		t.Fatalf("未配置 udp_only 时应默认为 true")
	}
}

// -c/--config 的四种写法都应被识别，且取最先出现者。
func TestExtractConfigFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{"short space", []string{"-c", "a.toml"}, "a.toml", true},
		{"long space", []string{"--config", "b.toml"}, "b.toml", true},
		{"long eq", []string{"--config=c.toml"}, "c.toml", true},
		{"short eq", []string{"-c=d.toml"}, "d.toml", true},
		{"single dash long", []string{"-config", "e.toml"}, "e.toml", true},
		{"absent", []string{"-i", "br-lan"}, "", false},
		{"missing value", []string{"-c"}, "", false},
		{"first wins", []string{"-c", "first.toml", "--config", "second.toml"}, "first.toml", true},
	}
	for _, c := range cases {
		got, ok := extractConfigFlag(c.args)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: extractConfigFlag(%v) = (%q,%v)，期望 (%q,%v)", c.name, c.args, got, ok, c.want, c.ok)
		}
	}
}

// 显式指定配置文件时只使用该文件（优先于默认候选）。
func TestLoadConfigExplicitPath(t *testing.T) {
	chdirTemp(t)
	if err := os.WriteFile("custom.toml", []byte("threshold = 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("config.toml", []byte("threshold = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := loadConfigFor("custom.toml", true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if res.Path != "custom.toml" || res.Config.Threshold != 42 {
		t.Fatalf("应使用显式指定的文件，got path=%s threshold=%d", res.Path, res.Config.Threshold)
	}
}

// 显式指定但文件不存在时应创建该文件。
func TestLoadConfigExplicitMissingCreates(t *testing.T) {
	chdirTemp(t)

	res, err := loadConfigFor("my.toml", true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if !res.Created || res.Path != "my.toml" {
		t.Fatalf("应创建指定文件，got created=%v path=%s", res.Created, res.Path)
	}
	if _, err := os.Stat("my.toml"); err != nil {
		t.Fatalf("指定文件应已创建：%v", err)
	}
}

// 显式指定的文件非法，或父目录不存在时应报错。
func TestLoadConfigExplicitErrors(t *testing.T) {
	chdirTemp(t)

	if err := os.WriteFile("bad.toml", []byte("oops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFor("bad.toml", true); err == nil {
		t.Fatalf("显式指定且非法时应报错")
	}
	if _, err := loadConfigFor("nodir/x.toml", true); err == nil {
		t.Fatalf("父目录不存在时应报错")
	}
}

// 黑名单以数组表 [[blacklist]] 配置，list_mode 大小写不敏感。
func TestConfigBlacklistTable(t *testing.T) {
	chdirTemp(t)

	content := "list_mode = \"BLACKLIST\"\n" +
		"[[blacklist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"[[blacklist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if res.Config.ListMode != listModeBlacklist {
		t.Fatalf("list_mode 解析错误：%q", res.Config.ListMode)
	}
	bl, wl, err := res.Config.listEntries()
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

	content := "list_mode = \"whitelist\"\n" +
		"[[whitelist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"[[whitelist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n" +
		"ports = [40000, 40001]\n" +
		"[[whitelist]]\n" +
		"mac = \"22:33:44:55:66:77\"\n" +
		"ports = [\"40000-40002\"]\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	bl, wl, err := res.Config.listEntries()
	if err != nil {
		t.Fatalf("转换失败：%v", err)
	}
	f, err := NewDeviceFilter(res.Config.ListMode, bl, wl)
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

	content := "list_mode = \"whitelist\"\n" +
		"[[whitelist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"enabled = false\n" +
		"[[whitelist]]\n" +
		"mac = \"11:22:33:44:55:66\"\n"
	if err := os.WriteFile("config.toml", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	bl, wl, err := res.Config.listEntries()
	if err != nil {
		t.Fatalf("转换失败：%v", err)
	}
	if len(bl) != 0 || len(wl) != 1 || wl[0] != "11:22:33:44:55:66" {
		t.Fatalf("enabled=false 条目应被跳过，got blacklist=%v whitelist=%v", bl, wl)
	}
}

// 黑名单带端口、或条目缺少 mac 时应被拒绝。
func TestConfigListInvalidEntries(t *testing.T) {
	chdirTemp(t)

	withPorts := "list_mode = \"blacklist\"\n" +
		"[[blacklist]]\n" +
		"mac = \"aa:bb:cc:dd:ee:ff\"\n" +
		"ports = [40000]\n"
	if err := os.WriteFile("config.toml", []byte(withPorts), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if _, _, err := res.Config.listEntries(); err == nil {
		t.Fatalf("黑名单带端口应报错")
	}

	noMac := "list_mode = \"blacklist\"\n" +
		"[[blacklist]]\n" +
		"enabled = true\n"
	if err := os.WriteFile("config.toml", []byte(noMac), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = LoadConfig()
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if _, _, err := res.Config.listEntries(); err == nil {
		t.Fatalf("缺少 mac 应报错")
	}
}

// 非法 list_mode 应导致解析失败。
func TestConfigListModeInvalid(t *testing.T) {
	if _, err := parseConfig([]byte("list_mode = \"foo\"\n")); err == nil {
		t.Fatalf("非法 list_mode 应报错")
	}
}

// parseByteSize 支持纯字节数与常见二进制单位。
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
		got, err := parseByteSize(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("parseByteSize(%q) = (%d,%v)，期望 (%d,nil)", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("parseByteSize(%q) 应报错，got (%d,nil)", c.in, got)
		}
	}
}
