package filter

import (
	"strings"
	"testing"
)

func mustFilter(t *testing.T, mode string, black, white []string) *DeviceFilter {
	t.Helper()
	f, err := NewDeviceFilter(mode, black, white)
	if err != nil {
		t.Fatalf("构建过滤器失败：%v", err)
	}
	return f
}

// 未配置名单时一律放行。
func TestFilterDisabled(t *testing.T) {
	var nilFilter *DeviceFilter
	if !nilFilter.Allow("aa:bb:cc:dd:ee:ff", 80) {
		t.Fatalf("nil 过滤器应一律放行")
	}
	f := mustFilter(t, ModeNone, nil, nil)
	if !f.Allow("aa:bb:cc:dd:ee:ff", 80) {
		t.Fatalf("未配置模式应一律放行")
	}
	if f.Enabled() {
		t.Fatalf("未配置模式不应视为启用")
	}
}

// 黑名单模式：只检测名单内设备（任意端口），名单外一律忽略。
func TestFilterBlacklistOnlyListed(t *testing.T) {
	f := mustFilter(t, ModeBlacklist, []string{"AA:BB:CC:DD:EE:FF"}, nil)

	if !f.Allow("aa:bb:cc:dd:ee:ff", 40000) {
		t.Fatalf("名单内设备应被检测")
	}
	if !f.Allow("aa:bb:cc:dd:ee:ff", 1) {
		t.Fatalf("名单内设备的任意端口都应被检测")
	}
	if f.Allow("11:22:33:44:55:66", 40000) {
		t.Fatalf("名单外设备不应被检测")
	}
}

// 白名单模式（不带端口）：该设备全部端口都不检测。
func TestFilterWhitelistAllPorts(t *testing.T) {
	f := mustFilter(t, ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff"})

	if f.Allow("aa:bb:cc:dd:ee:ff", 40000) || f.Allow("aa:bb:cc:dd:ee:ff", 1) {
		t.Fatalf("白名单设备的所有端口都不应被检测")
	}
	if !f.Allow("11:22:33:44:55:66", 40000) {
		t.Fatalf("白名单外设备应被检测")
	}
}

// 白名单模式（带端口）：只有指定端口不检测，同设备其它端口照常检测。
func TestFilterWhitelistSpecificPort(t *testing.T) {
	f := mustFilter(t, ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:40000"})

	if f.Allow("aa:bb:cc:dd:ee:ff", 40000) {
		t.Fatalf("白名单指定端口不应被检测")
	}
	if !f.Allow("aa:bb:cc:dd:ee:ff", 80) {
		t.Fatalf("白名单设备的其它端口应被检测")
	}
	if !f.Allow("11:22:33:44:55:66", 40000) {
		t.Fatalf("白名单外设备应被检测")
	}
}

// 白名单支持端口范围。
func TestFilterWhitelistPortRange(t *testing.T) {
	f := mustFilter(t, ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:40000-40002"})

	for _, p := range []uint16{40000, 40001, 40002} {
		if f.Allow("aa:bb:cc:dd:ee:ff", p) {
			t.Fatalf("范围内端口 %d 不应被检测", p)
		}
	}
	if !f.Allow("aa:bb:cc:dd:ee:ff", 40003) {
		t.Fatalf("范围外端口应被检测")
	}
}

// 白名单支持斜杠列表，且可与范围混用。
func TestFilterWhitelistSlashAndMixed(t *testing.T) {
	f := mustFilter(t, ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:80-82/9000"})

	for _, p := range []uint16{80, 81, 82, 9000} {
		if f.Allow("aa:bb:cc:dd:ee:ff", p) {
			t.Fatalf("端口 %d 不应被检测", p)
		}
	}
	if !f.Allow("aa:bb:cc:dd:ee:ff", 83) {
		t.Fatalf("未列出的端口应被检测")
	}
}

// 多个白名单条目对同一 MAC 的端口应合并。
func TestFilterWhitelistMergePorts(t *testing.T) {
	f := mustFilter(t, ModeWhitelist, nil, []string{
		"aa:bb:cc:dd:ee:ff:40000",
		"aa:bb:cc:dd:ee:ff:40001/40002",
	})

	for _, p := range []uint16{40000, 40001, 40002} {
		if f.Allow("aa:bb:cc:dd:ee:ff", p) {
			t.Fatalf("合并后的端口 %d 不应被检测", p)
		}
	}
	if !f.Allow("aa:bb:cc:dd:ee:ff", 40003) {
		t.Fatalf("未列出的端口应被检测")
	}
}

// 黑名单模式（带端口）：只有名单内指定端口会被检测，同设备其它端口忽略。
func TestFilterBlacklistSpecificPort(t *testing.T) {
	f := mustFilter(t, ModeBlacklist, []string{"aa:bb:cc:dd:ee:ff:40000"}, nil)

	if !f.Allow("aa:bb:cc:dd:ee:ff", 40000) {
		t.Fatalf("名单内指定端口应被检测")
	}
	if f.Allow("aa:bb:cc:dd:ee:ff", 80) {
		t.Fatalf("名单内设备的其它端口不应被检测")
	}
	if f.Allow("11:22:33:44:55:66", 40000) {
		t.Fatalf("名单外设备不应被检测")
	}
}

// 黑名单支持端口范围与斜杠列表。
func TestFilterBlacklistPortRange(t *testing.T) {
	f := mustFilter(t, ModeBlacklist, []string{"aa:bb:cc:dd:ee:ff:40000-40002/9000"}, nil)

	for _, p := range []uint16{40000, 40001, 40002, 9000} {
		if !f.Allow("aa:bb:cc:dd:ee:ff", p) {
			t.Fatalf("范围内端口 %d 应被检测", p)
		}
	}
	if f.Allow("aa:bb:cc:dd:ee:ff", 40003) {
		t.Fatalf("范围外端口不应被检测")
	}
}

// 条目格式错误应报错。
func TestFilterErrors(t *testing.T) {
	if _, err := NewDeviceFilter(ModeBlacklist, []string{"not-a-mac"}, nil); err == nil {
		t.Fatalf("非法 MAC 应报错")
	}
	if _, err := NewDeviceFilter(ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:70000"}); err == nil {
		t.Fatalf("非法端口应报错")
	}
	if _, err := NewDeviceFilter(ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:40010-40000"}); err == nil {
		t.Fatalf("倒置的端口范围应报错")
	}
	if _, err := NewDeviceFilter(ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:80//90"}); err == nil {
		t.Fatalf("空端口段应报错")
	}
}

// ParsePorts：解析整数与表达式字符串混合的端口数组。
func TestParsePorts(t *testing.T) {
	got, err := ParsePorts([]any{int64(53), "1000-1002", "2000/2002"})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	want := []uint16{53, 1000, 1001, 1002, 2000, 2002}
	if len(got) != len(want) {
		t.Fatalf("ParsePorts = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParsePorts = %v，期望 %v", got, want)
		}
	}

	if ports, err := ParsePorts(nil); err != nil || ports != nil {
		t.Fatalf("空数组应返回 nil,nil，got %v,%v", ports, err)
	}
	if _, err := ParsePorts([]any{"70000"}); err == nil {
		t.Fatalf("非法端口应报错")
	}
	if _, err := ParsePorts([]any{true}); err == nil {
		t.Fatalf("非法元素类型应报错")
	}
}

// 黑名单模式且名单为空时应被识别（用于启动校验）。
func TestFilterBlacklistEmpty(t *testing.T) {
	if !mustFilter(t, ModeBlacklist, nil, nil).Empty() {
		t.Fatalf("空黑名单应被判定为 Empty")
	}
	if mustFilter(t, ModeWhitelist, nil, nil).Empty() {
		t.Fatalf("白名单模式不应判定为 Empty")
	}
}

func TestFilterDescribe(t *testing.T) {
	cases := []struct {
		name string
		f    *DeviceFilter
		want string
	}{
		{"none", mustFilter(t, ModeNone, nil, nil), "未启用"},
		{"blacklist", mustFilter(t, ModeBlacklist, []string{"aa:bb:cc:dd:ee:ff"}, nil), "黑名单"},
		{"whitelist", mustFilter(t, ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff:40000"}), "白名单"},
	}
	for _, c := range cases {
		if !strings.Contains(c.f.Describe(), c.want) {
			t.Errorf("%s: Describe() = %q，未包含 %q", c.name, c.f.Describe(), c.want)
		}
	}
}
