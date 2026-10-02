package main

import (
	"testing"
	"time"
)

func offsetOf(loc *time.Location) int {
	_, off := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).In(loc).Zone()
	return off
}

func TestParsePOSIXTZ(t *testing.T) {
	cases := []struct {
		in   string
		want int // 期望的 UTC 偏移（秒）
	}{
		{"CST-8", 8 * 3600},
		{"AEST-10", 10 * 3600},
		{"EST5", -5 * 3600},
		{"UTC", 0},
		{"GMT0", 0},
		{"UTC+8", 8 * 3600}, // 日常习惯：UTC+8 指东八区
		{"+08:00", 8 * 3600},
		{"-05:00", -5 * 3600},
		{"+5:30", 5*3600 + 30*60},
		{"EST5EDT,M3.2.0,M11.1.0", -5 * 3600}, // 仅取标准时间
	}
	for _, c := range cases {
		loc, err := parsePOSIXTZ(c.in)
		if err != nil {
			t.Errorf("parsePOSIXTZ(%q) 出错: %v", c.in, err)
			continue
		}
		if got := offsetOf(loc); got != c.want {
			t.Errorf("parsePOSIXTZ(%q) 偏移=%d, 期望 %d", c.in, got, c.want)
		}
	}
}

func TestParsePOSIXTZInvalid(t *testing.T) {
	for _, in := range []string{"Asia/Shanghai", "CST/8", "", "  "} {
		if _, err := parsePOSIXTZ(in); err == nil {
			t.Errorf("parsePOSIXTZ(%q) 应返回错误", in)
		}
	}
}

func TestLoadLocationPOSIX(t *testing.T) {
	loc, err := loadLocation("CST-8")
	if err != nil {
		t.Fatalf("loadLocation(CST-8) 出错: %v", err)
	}
	if got := offsetOf(loc); got != 8*3600 {
		t.Fatalf("CST-8 偏移=%d, 期望 %d", got, 8*3600)
	}
}

func TestLoadLocationIANA(t *testing.T) {
	loc, err := loadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("系统缺少 tzdata，跳过 IANA 用例: %v", err)
	}
	if got := offsetOf(loc); got != 8*3600 {
		t.Fatalf("Asia/Shanghai 偏移=%d, 期望 %d", got, 8*3600)
	}
}
