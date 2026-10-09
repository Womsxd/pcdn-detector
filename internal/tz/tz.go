// Package tz 解析并加载日志时区：依次尝试 -tz 参数、TZ 环境变量、/etc/TZ（OpenWrt）。
package tz

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ResolveLocation 依次尝试 -tz 参数、TZ 环境变量、/etc/TZ（OpenWrt 使用 POSIX 时区串），
// 命中即返回，并附带来源描述；全部失败时回退到系统本地时区。
func ResolveLocation(flagTZ string) (*time.Location, string) {
	if flagTZ != "" {
		if loc, err := loadLocation(flagTZ); err == nil {
			return loc, "-tz 参数"
		} else {
			fmt.Fprintf(os.Stderr, "警告：无法识别时区 %q（%v），改用系统时区\n", flagTZ, err)
		}
	}

	if v := strings.TrimSpace(os.Getenv("TZ")); v != "" {
		if loc, err := loadLocation(v); err == nil {
			return loc, "TZ 环境变量"
		}
	}

	// OpenWrt 将时区写入 /etc/TZ（POSIX 串，如 CST-8），Go 默认不读取该文件。
	if data, err := os.ReadFile("/etc/TZ"); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			if loc, err := loadLocation(v); err == nil {
				return loc, "/etc/TZ"
			}
		}
	}

	return time.Local, "系统默认"
}

// loadLocation 支持 IANA 名称（如 Asia/Shanghai）与 POSIX 时区串（如 CST-8、UTC、+08:00）。
func loadLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("空的时区")
	}
	if name == "UTC" || name == "GMT" {
		return time.UTC, nil
	}
	if loc, err := time.LoadLocation(name); err == nil {
		return loc, nil
	}
	return parsePOSIXTZ(name)
}

// parsePOSIXTZ 解析 POSIX 时区串（如 CST-8、AEST-10、EST5EDT,M3.2.0,M11.1.0）。
// 仅取标准时间偏移，忽略夏令时规则；纯数字偏移（如 +08:00）按 ISO（即 UTC 偏移）处理。
func parsePOSIXTZ(s string) (*time.Location, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("空的时区")
	}

	// 纯数字偏移：+8 / -5 / +08:00 / 8。
	if s[0] == '+' || s[0] == '-' || (s[0] >= '0' && s[0] <= '9') {
		sign, body := 1, s
		if s[0] == '+' || s[0] == '-' {
			if s[0] == '-' {
				sign = -1
			}
			body = s[1:]
		}
		secs, ok := parseHMS(body)
		if !ok {
			return nil, fmt.Errorf("非法时区偏移: %q", s)
		}
		return time.FixedZone(s, sign*secs), nil
	}

	// 缩写 + 偏移。
	i, name := 0, ""
	if s[0] == '<' {
		j := strings.IndexByte(s, '>')
		if j < 0 {
			return nil, fmt.Errorf("非法时区缩写: %q", s)
		}
		name, i = s[1:j], j+1
	} else {
		for i < len(s) && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
			i++
		}
		name = s[:i]
		if i < len(s) {
			if c := s[i]; c != '+' && c != '-' && !(c >= '0' && c <= '9') {
				return nil, fmt.Errorf("非法时区: %q", s)
			}
		}
	}
	if name == "" {
		return nil, fmt.Errorf("非法时区: %q", s)
	}

	sign := 1
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		if s[i] == '-' {
			sign = -1
		}
		i++
	}
	secs, ok := parseHMS(s[i:])
	if !ok {
		secs = 0 // 仅给出缩写（如 UTC、GMT），偏移为 0。
	}

	// POSIX 约定：本地时间 + 偏移 = UTC，故 Go 偏移取相反数（CST-8 → UTC+8）。
	// 但 UTC/GMT 后的偏移按日常习惯（UTC+8 即东八区）处理，避免踩坑。
	if strings.EqualFold(name, "UTC") || strings.EqualFold(name, "GMT") {
		return time.FixedZone(name, sign*secs), nil
	}
	return time.FixedZone(name, -sign*secs), nil
}

// parseHMS 解析 hh、hh:mm、hh:mm:ss 形式的时长为秒数。
func parseHMS(s string) (int, bool) {
	end := 0
	for end < len(s) && (s[end] == ':' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	if end == 0 {
		return 0, false
	}
	parts := strings.Split(s[:end], ":")
	if len(parts) > 3 {
		return 0, false
	}
	vals := make([]int, 0, 3)
	for _, p := range parts {
		if p == "" {
			return 0, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, false
		}
		vals = append(vals, n)
	}
	secs := vals[0] * 3600
	if len(vals) > 1 {
		secs += vals[1] * 60
	}
	if len(vals) > 2 {
		secs += vals[2]
	}
	return secs, true
}
