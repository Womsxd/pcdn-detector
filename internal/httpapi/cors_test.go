//go:build !nohttp

package httpapi

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"pcdn-detect/internal/config"
)

// doWithHeader 与 testServer.do 类似，但同时返回响应头（CORS 断言需要）。
func (ts *testServer) doWithHeader(t *testing.T, method, path string, hdr map[string]string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.base+path, nil)
	if err != nil {
		t.Fatalf("构造请求失败：%v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败：%v", err)
	}
	return resp.StatusCode, resp.Header, b
}

func newCORSServer(t *testing.T, cfg config.HTTPConfig) *testServer {
	t.Helper()
	cfg.Enabled = true
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	srv, err := New(newTestDetector(), nil, cfg, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	return start(t, srv)
}

// 未配置 cors_allowed_origins 时不回写任何 CORS 头，预检按普通请求处理（405）。
func TestCORSDisabledByDefault(t *testing.T) {
	ts := newCORSServer(t, config.HTTPConfig{})

	code, hdr, _ := ts.doWithHeader(t, http.MethodGet, "/api/v1/health", map[string]string{"Origin": "https://a.example"})
	if code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("未启用 CORS 时不应回写允许来源，got %q", got)
	}

	code, _, _ = ts.doWithHeader(t, http.MethodOptions, "/api/v1/health", map[string]string{
		"Origin":                        "https://a.example",
		"Access-Control-Request-Method": "GET",
	})
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("未启用 CORS 的 OPTIONS 应为 405，got %d", code)
	}
}

// 命中允许来源时回显该来源（附带 Vary / 凭据头）；未命中不回写。
func TestCORSAllowedOrigin(t *testing.T) {
	ts := newCORSServer(t, config.HTTPConfig{
		CORSAllowedOrigins:   []string{"https://admin.example.com"},
		CORSAllowCredentials: true,
	})
	const origin = "https://admin.example.com"

	code, hdr, _ := ts.doWithHeader(t, http.MethodGet, "/api/v1/health", map[string]string{"Origin": origin})
	if code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("应回显允许来源 %q，got %q", origin, got)
	}
	if got := hdr.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("启用凭据时应回写 Allow-Credentials，got %q", got)
	}
	if !strings.Contains(strings.Join(hdr.Values("Vary"), ","), "Origin") {
		t.Fatalf("应带 Vary: Origin，got %v", hdr.Values("Vary"))
	}

	for _, o := range []string{"https://evil.example", ""} {
		h := map[string]string{}
		if o != "" {
			h["Origin"] = o
		}
		code, hdr, _ := ts.doWithHeader(t, http.MethodGet, "/api/v1/health", h)
		if code != http.StatusOK {
			t.Fatalf("Origin=%q 状态码 %d，期望 200", o, code)
		}
		if got := hdr.Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("Origin=%q 不应回写允许来源，got %q", o, got)
		}
		if got := hdr.Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("Origin=%q 不应回写凭据头，got %q", o, got)
		}
	}
}

// 未命中允许来源的预检返回 204，但不回写允许头，也不暴露路由允许的方法。
func TestCORSPreflightDisallowedOrigin(t *testing.T) {
	ts := newCORSServer(t, config.HTTPConfig{CORSAllowedOrigins: []string{"https://admin.example.com"}})

	code, hdr, _ := ts.doWithHeader(t, http.MethodOptions, "/api/v1/status", map[string]string{
		"Origin":                        "https://evil.example",
		"Access-Control-Request-Method": "GET",
	})
	if code != http.StatusNoContent {
		t.Fatalf("预检应返回 204，got %d", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("未允许来源不应回写允许来源，got %q", got)
	}
	if got := hdr.Get("Access-Control-Allow-Methods"); got != "" {
		t.Fatalf("未允许来源不应回写 Allow-Methods，got %q", got)
	}
}

// 通配来源回写 "*"，且不回写凭据头。
func TestCORSWildcard(t *testing.T) {
	ts := newCORSServer(t, config.HTTPConfig{CORSAllowedOrigins: []string{"*"}})

	code, hdr, _ := ts.doWithHeader(t, http.MethodGet, "/api/v1/status", map[string]string{"Origin": "https://any.example"})
	if code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("通配来源应回写 *，got %q", got)
	}
	if got := hdr.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("通配来源不应回写凭据头，got %q", got)
	}
}

// 预检在鉴权之前响应：无 Authorization 也能拿到 204；实际请求仍需鉴权。
func TestCORSPreflightBypassesAuth(t *testing.T) {
	ts := newCORSServer(t, config.HTTPConfig{
		Token:              "s3cr3t",
		CORSAllowedOrigins: []string{"https://admin.example.com"},
	})
	const origin = "https://admin.example.com"

	code, hdr, _ := ts.doWithHeader(t, http.MethodOptions, "/api/v1/status", map[string]string{
		"Origin":                         origin,
		"Access-Control-Request-Method":  "GET",
		"Access-Control-Request-Headers": "authorization,content-type",
	})
	if code != http.StatusNoContent {
		t.Fatalf("预检应返回 204，got %d", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("预检应回写允许来源，got %q", got)
	}
	if got := hdr.Get("Access-Control-Allow-Methods"); got != "GET, HEAD" {
		t.Fatalf("Allow-Methods 不符：%q", got)
	}
	if got := hdr.Get("Access-Control-Allow-Headers"); got != "authorization,content-type" {
		t.Fatalf("Allow-Headers 应回显请求头，got %q", got)
	}
	if got := hdr.Get("Access-Control-Max-Age"); got != "600" {
		t.Fatalf("Max-Age 默认应为 600，got %q", got)
	}

	// 未带 Authorization 的实际请求仍 401，但应带 CORS 头，便于前端读取错误。
	code, hdr, _ = ts.doWithHeader(t, http.MethodGet, "/api/v1/status", map[string]string{"Origin": origin})
	if code != http.StatusUnauthorized {
		t.Fatalf("实际请求应 401，got %d", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("401 响应也应带允许来源，got %q", got)
	}

	// 带 token 的实际请求 200。
	code, hdr, _ = ts.doWithHeader(t, http.MethodGet, "/api/v1/status", map[string]string{
		"Origin":        origin,
		"Authorization": "Bearer s3cr3t",
	})
	if code != http.StatusOK {
		t.Fatalf("带 token 应 200，got %d", code)
	}
	if got := hdr.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("200 响应应带允许来源，got %q", got)
	}
}

// 预检的路径 / 方法语义与普通请求一致：未知路径 404，未注册方法 405 + Allow。
func TestCORSPreflightRouting(t *testing.T) {
	ts := newCORSServer(t, config.HTTPConfig{CORSAllowedOrigins: []string{"*"}})

	code, _, _ := ts.doWithHeader(t, http.MethodOptions, "/api/v1/nope", map[string]string{
		"Origin":                        "https://any.example",
		"Access-Control-Request-Method": "GET",
	})
	if code != http.StatusNotFound {
		t.Fatalf("未知路径预检应 404，got %d", code)
	}

	code, hdr, _ := ts.doWithHeader(t, http.MethodOptions, "/api/v1/status", map[string]string{
		"Origin":                        "https://any.example",
		"Access-Control-Request-Method": "POST",
	})
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("未注册方法预检应 405，got %d", code)
	}
	if got := hdr.Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow 头不符：%q", got)
	}
}

// SetCORS 热更新：无需重启即可切换策略。
func TestSetCORS(t *testing.T) {
	srv, err := New(newTestDetector(), nil, config.HTTPConfig{Enabled: true, Listen: "127.0.0.1:8080"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	code, _, _ := ts.doWithHeader(t, http.MethodGet, "/api/v1/health", map[string]string{"Origin": "https://a.example"})
	if code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200", code)
	}

	srv.SetCORS([]string{"https://a.example"}, false, 0)
	_, hdr, _ := ts.doWithHeader(t, http.MethodGet, "/api/v1/health", map[string]string{"Origin": "https://a.example"})
	if got := hdr.Get("Access-Control-Allow-Origin"); got != "https://a.example" {
		t.Fatalf("SetCORS 后应回写允许来源，got %q", got)
	}

	code, hdr, _ = ts.doWithHeader(t, http.MethodOptions, "/api/v1/health", map[string]string{
		"Origin":                        "https://a.example",
		"Access-Control-Request-Method": "GET",
	})
	if code != http.StatusNoContent {
		t.Fatalf("SetCORS 后预检应 204，got %d", code)
	}
	if got := hdr.Get("Access-Control-Max-Age"); got != "" {
		t.Fatalf("maxAge=0 时不应回写 Max-Age，got %q", got)
	}

	// 关闭 CORS。
	srv.SetCORS(nil, false, 600)
	_, hdr, _ = ts.doWithHeader(t, http.MethodGet, "/api/v1/health", map[string]string{"Origin": "https://a.example"})
	if got := hdr.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("关闭 CORS 后不应回写允许来源，got %q", got)
	}
}
