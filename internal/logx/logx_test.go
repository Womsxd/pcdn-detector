package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug":    LevelDebug,
		"INFO":     LevelInfo,
		"warn":     LevelWarn,
		" warning": LevelWarn,
		"error":    LevelError,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Fatalf("ParseLevel(%q) = %v, %v；期望 %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("非法等级应返回错误")
	}
}

func TestLoggerFiltersByLevel(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, "", 0)
	lg.SetLevel(LevelWarn)

	lg.Infof("已封禁设备 a")
	lg.Warnf("警告：a")
	lg.Errorf("解封失败：%v", "b")

	out := buf.String()
	if strings.Contains(out, "已封禁") {
		t.Fatalf("warn 等级下不应输出 info 日志：%s", out)
	}
	if !strings.Contains(out, "警告：a") || !strings.Contains(out, "解封失败：b") {
		t.Fatalf("warn 及以上等级应输出：%s", out)
	}
}

func TestLoggerDefaultLevelOutputsAll(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, "", 0)
	lg.Debugf("dbg")
	lg.Infof("inf")
	if !strings.Contains(buf.String(), "dbg") || !strings.Contains(buf.String(), "inf") {
		t.Fatalf("默认等级应输出全部日志：%s", buf.String())
	}
}

func TestNilLoggerIsSafe(t *testing.T) {
	var lg *Logger
	lg.Infof("noop")
	lg.SetLevel(LevelError)
	if lg.Enabled(LevelError) {
		t.Fatal("nil logger 不应输出任何日志")
	}
}
