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

// 无任何配置文件时应创建默认配置 pcdn-detect.conf。
func TestConfigCreatedWhenMissing(t *testing.T) {
	chdirTemp(t)

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if !res.Created {
		t.Fatalf("应标记为新建默认配置")
	}
	if res.Path != "pcdn-detect.conf" {
		t.Fatalf("默认配置文件名应为 pcdn-detect.conf，got %s", res.Path)
	}
	if _, err := os.Stat("pcdn-detect.conf"); err != nil {
		t.Fatalf("默认配置文件应已创建：%v", err)
	}
	if res.Config.Threshold != defaultThreshold {
		t.Fatalf("阈值默认值应为 %d，got %d", defaultThreshold, res.Config.Threshold)
	}
	if res.Config.Window != defaultWindow {
		t.Fatalf("窗口默认值应为 %s，got %s", defaultWindow, res.Config.Window)
	}
	if res.Config.Promisc == nil || !*res.Config.Promisc {
		t.Fatalf("混杂模式默认应为 true")
	}
}

// 存在 config.conf 时应优先加载，支持注释、内联注释、引号与别名。
func TestConfigLoadedFromCandidate(t *testing.T) {
	chdirTemp(t)

	content := "# 这是注释\n" +
		"\n" +
		`interface = "br-lan"   # 内联注释` + "\n" +
		"threshold = 33\n" +
		"window = 2m\n" +
		"alert_duration = 90s\n" +
		"promisc = false\n" +
		"interval = 5s\n" +
		"tz = Asia/Shanghai\n"
	if err := os.WriteFile("config.conf", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if res.Created {
		t.Fatalf("已有配置不应再创建默认文件")
	}
	if res.Path != "config.conf" {
		t.Fatalf("应加载 config.conf，got %s", res.Path)
	}
	if res.Config.Interface != "br-lan" {
		t.Fatalf("引号/内联注释解析错误：%q", res.Config.Interface)
	}
	if res.Config.Threshold != 33 {
		t.Fatalf("threshold 解析错误：%d", res.Config.Threshold)
	}
	if res.Config.Window != 2*time.Minute ||
		res.Config.AlertDuration != 90*time.Second ||
		res.Config.Interval != 5*time.Second {
		t.Fatalf("时长字段解析错误：%+v", res.Config)
	}
	if res.Config.Promisc == nil || *res.Config.Promisc {
		t.Fatalf("promisc 应为 false")
	}
	if res.Config.Timezone != "Asia/Shanghai" {
		t.Fatalf("tz 别名解析错误：%q", res.Config.Timezone)
	}
	if _, err := os.Stat("pcdn-detect.conf"); err == nil {
		t.Fatalf("加载成功后不应创建默认配置")
	}
}

// 前一个候选加载失败时应继续往下读，并记录警告。
func TestConfigFallsThroughInvalid(t *testing.T) {
	chdirTemp(t)

	// config.conf 缺少 '='。
	if err := os.WriteFile("config.conf", []byte("threshold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("pcdn-detect.conf", []byte("threshold = 7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if res.Path != "pcdn-detect.conf" {
		t.Fatalf("应回退加载 pcdn-detect.conf，got %s", res.Path)
	}
	if res.Config.Threshold != 7 {
		t.Fatalf("阈值应来自 pcdn-detect.conf，got %d", res.Config.Threshold)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("跳过的非法配置应产生警告")
	}
}

// 无法加载且默认文件已存在（无法创建）时应报错。
func TestConfigErrorWhenCannotCreate(t *testing.T) {
	chdirTemp(t)

	// 存在但非法，且这是唯一的创建目标，导致无法创建。
	if err := os.WriteFile("pcdn-detect.conf", []byte("bogus = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(); err == nil {
		t.Fatalf("无法加载且无法创建时应报错")
	}
}

// 时长字段支持纯数字（按秒）与字符串两种写法。
func TestConfigDurationForms(t *testing.T) {
	chdirTemp(t)

	content := "window = 90\ninterval = 3s\n"
	if err := os.WriteFile("config.conf", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败：%v", err)
	}
	if res.Config.Window != 90*time.Second {
		t.Fatalf("纯数字应按秒解析，got %s", res.Config.Window)
	}
	if res.Config.Interval != 3*time.Second {
		t.Fatalf("字符串时长解析错误，got %s", res.Config.Interval)
	}
}

// 未知配置项应视为解析失败。
func TestConfigUnknownKey(t *testing.T) {
	if _, err := parseConfig([]byte("threshhold = 20\n")); err == nil {
		t.Fatalf("未知配置项应报错")
	}
}

// -f/--config 的四种写法都应被识别，且取最先出现者。
func TestExtractConfigFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{"short space", []string{"-f", "a.conf"}, "a.conf", true},
		{"long space", []string{"--config", "b.conf"}, "b.conf", true},
		{"long eq", []string{"--config=c.conf"}, "c.conf", true},
		{"short eq", []string{"-f=d.conf"}, "d.conf", true},
		{"single dash long", []string{"-config", "e.conf"}, "e.conf", true},
		{"absent", []string{"-i", "br-lan"}, "", false},
		{"missing value", []string{"-f"}, "", false},
		{"first wins", []string{"-f", "first.conf", "--config", "second.conf"}, "first.conf", true},
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
	if err := os.WriteFile("custom.conf", []byte("threshold = 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("config.conf", []byte("threshold = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := loadConfigFor("custom.conf", true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if res.Path != "custom.conf" || res.Config.Threshold != 42 {
		t.Fatalf("应使用显式指定的文件，got path=%s threshold=%d", res.Path, res.Config.Threshold)
	}
}

// 显式指定但文件不存在时应创建该文件。
func TestLoadConfigExplicitMissingCreates(t *testing.T) {
	chdirTemp(t)

	res, err := loadConfigFor("my.conf", true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if !res.Created || res.Path != "my.conf" {
		t.Fatalf("应创建指定文件，got created=%v path=%s", res.Created, res.Path)
	}
	if _, err := os.Stat("my.conf"); err != nil {
		t.Fatalf("指定文件应已创建：%v", err)
	}
}

// 显式指定的文件非法，或父目录不存在时应报错。
func TestLoadConfigExplicitErrors(t *testing.T) {
	chdirTemp(t)

	if err := os.WriteFile("bad.conf", []byte("oops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFor("bad.conf", true); err == nil {
		t.Fatalf("显式指定且非法时应报错")
	}
	if _, err := loadConfigFor("nodir/x.conf", true); err == nil {
		t.Fatalf("父目录不存在时应报错")
	}
}
