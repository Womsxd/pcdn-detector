package config

import (
	"os"
	"path/filepath"
	"testing"
)

// [http] 各项应被正确解析。
func TestHTTPConfigParse(t *testing.T) {
	data := []byte(`[http]
enabled = true
listen = "0.0.0.0:9090"
token = "secret"
device_ip_limit = 25
state_dir = "/run/pcdn"
`)
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("解析配置失败：%v", err)
	}
	h := cfg.HTTP
	if !h.Enabled || h.Listen != "0.0.0.0:9090" || h.Token != "secret" || h.StateDir != "/run/pcdn" {
		t.Fatalf("解析结果不符：%+v", h)
	}
	if h.ListenAddr() != "0.0.0.0:9090" {
		t.Fatalf("ListenAddr 应为 0.0.0.0:9090，got %q", h.ListenAddr())
	}
	if h.DeviceIPLimitValue() != 25 {
		t.Fatalf("DeviceIPLimitValue 应为 25，got %d", h.DeviceIPLimitValue())
	}
	if h.StateDirPath() != "/run/pcdn" {
		t.Fatalf("StateDirPath 应为 /run/pcdn，got %q", h.StateDirPath())
	}
	if h.StateFilePath() != "/run/pcdn/pcdn-detect.state" {
		t.Fatalf("StateFilePath 不符：%q", h.StateFilePath())
	}
}

// [http] 未配置时的默认值。
func TestHTTPDefaults(t *testing.T) {
	cfg := DefaultConfig()
	h := cfg.HTTP
	if h.ListenAddr() != defaultHTTPListen {
		t.Fatalf("ListenAddr 默认应为 %q，got %q", defaultHTTPListen, h.ListenAddr())
	}
	if h.DeviceIPLimitValue() != defaultDeviceIPLimit {
		t.Fatalf("DeviceIPLimitValue 默认应为 %d，got %d", defaultDeviceIPLimit, h.DeviceIPLimitValue())
	}
	if h.StateDirPath() != os.TempDir() {
		t.Fatalf("StateDirPath 默认应为系统临时目录 %q，got %q", os.TempDir(), h.StateDirPath())
	}
	if h.StateFilePath() != filepath.Join(os.TempDir(), stateFileName) {
		t.Fatalf("StateFilePath 不符：%q", h.StateFilePath())
	}
}

// 显式 <=0 的 device_ip_limit 回退到默认值。
func TestHTTPDeviceIPLimitFallback(t *testing.T) {
	zero := 0
	neg := -3
	for _, v := range []*int{&zero, &neg, nil} {
		h := HTTPConfig{DeviceIPLimit: v}
		if h.DeviceIPLimitValue() != defaultDeviceIPLimit {
			t.Fatalf("device_ip_limit=%v 应回退到默认 %d，got %d", v, defaultDeviceIPLimit, h.DeviceIPLimitValue())
		}
	}
}

// applyDefaults 应补上 listen 默认值。
func TestHTTPApplyDefaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HTTP.Listen = ""
	cfg.applyDefaults()
	if cfg.HTTP.Listen != defaultHTTPListen {
		t.Fatalf("applyDefaults 后 listen 应为 %q，got %q", defaultHTTPListen, cfg.HTTP.Listen)
	}
}

// [http] 下的未知键仍应报错（严格解析）。
func TestHTTPUnknownKey(t *testing.T) {
	_, err := parseConfig([]byte("[http]\nenabled = true\nbogus = 1\n"))
	if err == nil {
		t.Fatalf("未知配置项应报错")
	}
}

// token = "allow-no-token" 应表示关闭鉴权；普通 token 不受影响。
func TestHTTPAllowNoToken(t *testing.T) {
	h := HTTPConfig{Token: TokenAllowNoToken}
	if !h.NoToken() {
		t.Fatalf("NoToken 应为 true")
	}
	if h.BearerToken() != "" {
		t.Fatalf("BearerToken 应为空，got %q", h.BearerToken())
	}

	h2 := HTTPConfig{Token: "secret"}
	if h2.NoToken() || h2.BearerToken() != "secret" {
		t.Fatalf("普通 token 处理有误：%+v", h2)
	}
}

// [http] CORS 配置解析与默认值。
func TestHTTPCORSConfig(t *testing.T) {
	data := []byte(`[http]
enabled = true
cors_allowed_origins = ["https://admin.example.com", "http://192.168.1.10:5173"]
cors_allow_credentials = true
cors_max_age = 60
`)
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("解析配置失败：%v", err)
	}
	h := cfg.HTTP
	if !h.CORSEnabled() || h.CORSAnyOrigin() {
		t.Fatalf("CORS 启用状态不符：enabled=%v any=%v", h.CORSEnabled(), h.CORSAnyOrigin())
	}
	if len(h.CORSAllowedOrigins) != 2 || !h.CORSAllowCredentials {
		t.Fatalf("CORS 解析结果不符：%+v", h)
	}
	if h.CORSMaxAgeValue() != 60 {
		t.Fatalf("CORSMaxAgeValue 应为 60，got %d", h.CORSMaxAgeValue())
	}

	// 未配置时：不启用 CORS，Max-Age 用默认值。
	def := DefaultConfig().HTTP
	if def.CORSEnabled() || def.CORSAnyOrigin() {
		t.Fatalf("默认不应启用 CORS")
	}
	if def.CORSMaxAgeValue() != defaultCORSMaxAge {
		t.Fatalf("CORSMaxAgeValue 默认应为 %d，got %d", defaultCORSMaxAge, def.CORSMaxAgeValue())
	}
}

// CORS 来源与凭据组合应被校验：非法来源、非法 scheme、带路径 / 查询、通配 + 凭据、负的 max_age。
func TestHTTPCORSValidate(t *testing.T) {
	base := HTTPConfig{Enabled: true, Listen: "127.0.0.1:8080"}
	ok := []HTTPConfig{
		{CORSAllowedOrigins: []string{"*"}},
		{CORSAllowedOrigins: []string{"https://admin.example.com"}},
		{CORSAllowedOrigins: []string{"http://[::1]:5173"}},
		{CORSAllowedOrigins: []string{"https://admin.example.com/"}},
		{CORSAllowedOrigins: []string{"https://admin.example.com"}, CORSAllowCredentials: true},
	}
	for _, c := range ok {
		h := base
		h.CORSAllowedOrigins = c.CORSAllowedOrigins
		h.CORSAllowCredentials = c.CORSAllowCredentials
		if err := h.Validate(); err != nil {
			t.Fatalf("来源 %v 应通过校验：%v", c.CORSAllowedOrigins, err)
		}
	}

	neg := -1
	bad := []HTTPConfig{
		{CORSAllowedOrigins: []string{""}},
		{CORSAllowedOrigins: []string{"example.com"}},
		{CORSAllowedOrigins: []string{"ftp://admin.example.com"}},
		{CORSAllowedOrigins: []string{"https://*.admin.example.com"}},
		{CORSAllowedOrigins: []string{"https://admin.example.com/path"}},
		{CORSAllowedOrigins: []string{"https://admin.example.com?x=1"}},
		{CORSAllowedOrigins: []string{"*"}, CORSAllowCredentials: true},
		{CORSMaxAge: &neg},
	}
	for _, c := range bad {
		h := base
		h.CORSAllowedOrigins = c.CORSAllowedOrigins
		h.CORSAllowCredentials = c.CORSAllowCredentials
		h.CORSMaxAge = c.CORSMaxAge
		if err := h.Validate(); err == nil {
			t.Fatalf("来源 %v（凭据=%v）应校验失败", c.CORSAllowedOrigins, c.CORSAllowCredentials)
		}
	}
}

// 默认配置模板（含新增 [http] 段）应可被严格解析。
func TestDefaultTemplateParses(t *testing.T) {
	if _, err := parseConfig([]byte(defaultConfigTemplate)); err != nil {
		t.Fatalf("默认配置模板应可解析：%v", err)
	}
}
