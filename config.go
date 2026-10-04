package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 内置默认值，同时作为命令行参数的默认值与配置文件中缺失项的兜底。
const (
	defaultThreshold     = 20
	defaultWindow        = 60 * time.Second
	defaultAlertDuration = 10 * time.Minute
	defaultInterval      = 2 * time.Second
	defaultPromisc       = true
)

// configCandidates 是启动时按顺序尝试加载的配置文件名。
// 前一个不存在或加载失败时，继续尝试下一个（“往下读”）。
var configCandidates = []string{
	"config.conf",
	"pcdn-detect.conf",
}

// configCreateNames 是全部加载失败后，尝试创建默认配置的文件名（按顺序）。
var configCreateNames = []string{
	"pcdn-detect.conf",
}

// defaultConfigTemplate 是自动生成的配置模板（带注释，便于使用者修改）。
const defaultConfigTemplate = `# pcdn-detect 配置文件（首次启动自动生成于当前工作目录）
#
# 格式：每行一个「键 = 值」，以 # 开头的整行为注释，行尾也可用 # 追加注释；
#       值两端的引号可选（形如 interface = "br-lan"）。
# 命令行参数优先于本文件：显式指定的参数会覆盖此处的同名配置。

# 要监听的网卡名称（必填），例如 br-lan、br0、eth0
interface =

# 触发次数：同一设备同一端口在检测时长内出现的不同远端公网 IP 数量达到该值即判定疑似 PCDN
threshold = 20

# 检测时长（滑动窗口），支持 60s、5m、1h，也接受纯秒数
window = 60s

# 持续提示时长：期间出现新对端则刷新计时器，超过该时长无新对端则输出「PCDN行为结束」并静默
alert_duration = 10m

# 是否开启混杂模式（true/false）
promisc = true

# 检测扫描间隔
interval = 2s

# 日志时区：IANA 名称（如 Asia/Shanghai）或 POSIX 串（如 CST-8）；留空表示自动读取系统时区
timezone =
`

// Config 对应配置文件内容。
type Config struct {
	Interface     string
	Threshold     int
	Window        time.Duration
	AlertDuration time.Duration
	Promisc       *bool
	Interval      time.Duration
	Timezone      string
}

// defaultConfig 返回使用内置默认值的配置。
func defaultConfig() *Config {
	promisc := defaultPromisc
	return &Config{
		Threshold:     defaultThreshold,
		Window:        defaultWindow,
		AlertDuration: defaultAlertDuration,
		Promisc:       &promisc,
		Interval:      defaultInterval,
	}
}

// applyDefaults 为配置中缺失或非法的项填充内置默认值。
func (c *Config) applyDefaults() {
	if c.Threshold <= 0 {
		c.Threshold = defaultThreshold
	}
	if c.Window <= 0 {
		c.Window = defaultWindow
	}
	if c.AlertDuration <= 0 {
		c.AlertDuration = defaultAlertDuration
	}
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.Promisc == nil {
		promisc := defaultPromisc
		c.Promisc = &promisc
	}
}

// parseConfig 解析「键 = 值」格式的配置内容。
// 空行与 # 注释行会被忽略；未知键、缺少 = 的行视为错误。
func parseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		key, val, ok, err := parseConfigLine(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("第 %d 行：%w", lineNo, err)
		}
		if !ok {
			continue
		}
		if err := cfg.set(key, val); err != nil {
			return nil, fmt.Errorf("第 %d 行：%w", lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseConfigLine 解析单行，返回键、值与是否为有效配置行。
func parseConfigLine(raw string) (key, val string, ok bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false, nil
	}
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", "", false, fmt.Errorf("缺少 '='：%q", raw)
	}
	key = normalizeKey(strings.TrimSpace(s[:i]))
	if key == "" {
		return "", "", false, fmt.Errorf("键名为空：%q", raw)
	}
	val, err = unquote(stripInlineComment(strings.TrimSpace(s[i+1:])))
	if err != nil {
		return "", "", false, err
	}
	return key, val, true, nil
}

// normalizeKey 统一键名：转小写、'-' 归并为 '_'，并处理少量别名。
func normalizeKey(key string) string {
	key = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	switch key {
	case "iface":
		return "interface"
	case "tz":
		return "timezone"
	case "duration":
		return "window"
	}
	return key
}

// stripInlineComment 去掉引号之外的、以 '#' 起始的行尾注释。
func stripInlineComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#':
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// unquote 去掉值两端成对的引号；引号未闭合时报错。
func unquote(s string) (string, error) {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1], nil
	}
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		return "", fmt.Errorf("引号未闭合：%q", s)
	}
	return s, nil
}

// set 按归一化后的键写入对应字段。
func (c *Config) set(key, val string) error {
	switch key {
	case "interface":
		c.Interface = val
	case "threshold":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("threshold 需要整数，得到 %q", val)
		}
		c.Threshold = n
	case "window":
		d, err := parseDuration(val)
		if err != nil {
			return fmt.Errorf("window %w", err)
		}
		c.Window = d
	case "alert_duration":
		d, err := parseDuration(val)
		if err != nil {
			return fmt.Errorf("alert_duration %w", err)
		}
		c.AlertDuration = d
	case "promisc":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("promisc %w", err)
		}
		c.Promisc = &b
	case "interval":
		d, err := parseDuration(val)
		if err != nil {
			return fmt.Errorf("interval %w", err)
		}
		c.Interval = d
	case "timezone":
		c.Timezone = val
	default:
		return fmt.Errorf("未知配置项 %q", key)
	}
	return nil
}

// parseDuration 支持 60s/5m/1h 写法，也接受纯数字（按秒）。空值返回 0。
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("格式无效 %q（示例：60s、5m、1h 或纯秒数）", s)
	}
	return d, nil
}

// parseBool 解析布尔值，接受 true/false/1/0/yes/no/on/off。
func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("需要布尔值（true/false），得到 %q", s)
}

// configResult 描述一次配置加载的结果。
type configResult struct {
	Config   *Config
	Path     string   // 实际使用的配置文件路径（创建时为新建文件）
	Created  bool     // 是否为本次新建的默认配置文件
	Warnings []string // 加载过程中被跳过的候选文件说明
}

// LoadConfig 按默认候选顺序加载配置（等价于 loadConfig(configCandidates, configCreateNames)）。
func LoadConfig() (*configResult, error) {
	return loadConfig(configCandidates, configCreateNames)
}

// loadConfigFor 在显式指定配置文件时仅使用该文件，否则走默认候选顺序。
func loadConfigFor(explicitPath string, hasExplicit bool) (*configResult, error) {
	if hasExplicit {
		return loadConfig([]string{explicitPath}, []string{explicitPath})
	}
	return loadConfig(configCandidates, configCreateNames)
}

// loadConfig 按 candidates 顺序查找并加载配置文件：
//   - 找到且解析成功：使用该配置；
//   - 存在但解析/读取失败：记录警告并继续尝试下一个候选；
//   - 全部候选都不可用：尝试创建 createNames 中的默认配置文件；
//   - 创建目标已存在导致无法创建：返回错误。
func loadConfig(candidates, createNames []string) (*configResult, error) {
	var warnings []string
	for _, name := range candidates {
		data, err := os.ReadFile(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("读取配置文件 %s 失败，已跳过：%v", name, err))
			continue
		}
		cfg, err := parseConfig(data)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("解析配置文件 %s 失败，已跳过：%v", name, err))
			continue
		}
		cfg.applyDefaults()
		return &configResult{Config: cfg, Path: name, Warnings: warnings}, nil
	}

	// 没有任何可加载的配置：创建默认配置文件。
	name, err := createDefaultConfig(createNames)
	if err != nil {
		if len(warnings) > 0 {
			return nil, fmt.Errorf("%v；且创建默认配置失败：%w", warnings[len(warnings)-1], err)
		}
		return nil, err
	}
	return &configResult{Config: defaultConfig(), Path: name, Created: true, Warnings: warnings}, nil
}

// createDefaultConfig 依次尝试用 names 创建默认配置文件。
// 某个名字已存在时尝试下一个；若全部已存在或创建失败，则返回错误。
func createDefaultConfig(names []string) (string, error) {
	for _, name := range names {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // 名字被占用，尝试下一个
			}
			return "", fmt.Errorf("创建配置文件 %s 失败：%w", name, err)
		}
		if _, err := f.WriteString(defaultConfigTemplate); err != nil {
			f.Close()
			return "", fmt.Errorf("写入配置文件 %s 失败：%w", name, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("关闭配置文件 %s 失败：%w", name, err)
		}
		return name, nil
	}
	return "", fmt.Errorf("配置文件 %s 均已存在，无法创建默认配置", strings.Join(names, "/"))
}
