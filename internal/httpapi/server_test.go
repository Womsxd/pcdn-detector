package httpapi

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/netutil"
)

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func newTestDetector() *detector.Detector {
	return detector.NewDetector(20, time.Minute, 10*time.Minute, nil, testLogger(), false, false, 1000)
}

func observe(det *detector.Detector, macStr string, port uint16, remote string) {
	mac, _ := netutil.ParseMAC(macStr)
	det.Observe(detector.Observation{
		MAC:       mac,
		IP:        netip.MustParseAddr("192.168.1.2"),
		LocalPort: port,
		RemoteIP:  netip.MustParseAddr(remote),
		Up:        true,
		Proto:     netutil.ProtoUDP,
		Length:    100,
		TS:        time.Now(),
	})
}

func intPtr(v int) *int { return &v }

// 非回环地址 + 空 token 应拒绝构建。
func TestNewRejectsNonLoopbackWithoutToken(t *testing.T) {
	_, err := New(nil, nil, config.HTTPConfig{Listen: "0.0.0.0:8080"}, nil, testLogger())
	if err == nil {
		t.Fatalf("非回环地址且无 token 时应报错")
	}
	// 回环地址无需 token。
	if _, err := New(nil, nil, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, testLogger()); err != nil {
		t.Fatalf("回环地址不应报错：%v", err)
	}
	// 非回环 + token 允许。
	if _, err := New(nil, nil, config.HTTPConfig{Listen: "0.0.0.0:8080", Token: "x"}, nil, testLogger()); err != nil {
		t.Fatalf("非回环 + token 不应报错：%v", err)
	}
}

// Bearer 鉴权：缺失 / 错误 401，正确 200。
func TestAuth(t *testing.T) {
	srv, err := New(newTestDetector(), nil, config.HTTPConfig{Listen: "127.0.0.1:8080", Token: "s3cr3t"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	h := srv.Handler()

	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong", "Bearer nope", http.StatusUnauthorized},
		{"ok", "Bearer s3cr3t", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("%s: 状态码 %d，期望 %d", tc.name, rr.Code, tc.want)
		}
	}
}

// /devices 应受 device_ip_limit 约束并标记 truncated。
func TestDevicesIPLimit(t *testing.T) {
	det := newTestDetector()
	for i := 0; i < 5; i++ {
		observe(det, "aa:bb:cc:dd:ee:ff", 40000, netip.AddrFrom4([4]byte{1, 1, 1, byte(i + 1)}).String())
	}
	srv, err := New(det, nil, config.HTTPConfig{Listen: "127.0.0.1:8080", DeviceIPLimit: intPtr(3)}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("状态码 %d", rr.Code)
	}
	var snap detector.Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(snap.Devices) != 1 || len(snap.Devices[0].Ports) != 1 {
		t.Fatalf("设备/端口数不符：%+v", snap)
	}
	p := snap.Devices[0].Ports[0]
	if !p.Truncated || len(p.PeerIPs) != 3 || p.PeerCount != 5 {
		t.Fatalf("截断不符：truncated=%v len=%d count=%d", p.Truncated, len(p.PeerIPs), p.PeerCount)
	}
}

// /status 与 /dev/memory 应可访问且含关键字段。
func TestStatusAndMemory(t *testing.T) {
	det := newTestDetector()
	for i := 0; i < 3; i++ {
		observe(det, "aa:bb:cc:dd:ee:ff", 40000, netip.AddrFrom4([4]byte{1, 1, 1, byte(i + 1)}).String())
	}
	srv, err := New(det, nil, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	h := srv.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/status 状态码 %d", rr.Code)
	}
	var st statusView
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatalf("解析 status 失败：%v", err)
	}
	if st.Status != "ok" || st.TrackedDevices != 1 {
		t.Fatalf("status 不符：%+v", st)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/dev/memory", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/dev/memory 状态码 %d", rr.Code)
	}
	var mv memoryView
	if err := json.Unmarshal(rr.Body.Bytes(), &mv); err != nil {
		t.Fatalf("解析 memory 失败：%v", err)
	}
	if mv.GoVersion == "" || mv.Goroutines <= 0 {
		t.Fatalf("memory 字段不全：%+v", mv)
	}
}

// blk 为 nil 时 /blocks 返回空、/unban 返回 503。
func TestNilBlocker(t *testing.T) {
	srv, err := New(newTestDetector(), nil, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	h := srv.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/blocks", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/blocks 状态码 %d", rr.Code)
	}
	var empty blocker.Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &empty); err != nil {
		t.Fatalf("/blocks 应返回合法 JSON：%v", err)
	}
	if len(empty.Bans) != 0 {
		t.Fatalf("/blocks 无防火墙时应为空，got %+v", empty)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/unban",
		strings.NewReader(`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/unban 无防火墙应 503，got %d", rr.Code)
	}
}

// /reload 返回注入结果的字段。
func TestReload(t *testing.T) {
	var called bool
	reload := func() (ReloadResult, error) {
		called = true
		return ReloadResult{Applied: []string{"filter"}, RestartRequired: []string{"capture"}, Restarting: true}, nil
	}
	srv, err := New(nil, nil, config.HTTPConfig{Listen: "127.0.0.1:8080"}, reload, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/reload 状态码 %d", rr.Code)
	}
	if !called {
		t.Fatalf("ReloadFunc 未被调用")
	}
	var res ReloadResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if !res.Restarting || len(res.Applied) != 1 || len(res.RestartRequired) != 1 {
		t.Fatalf("reload 结果不符：%+v", res)
	}
}

// 真实 blocker：/blocks 展示封禁，/unban 解封。
func TestBlocksAndUnban(t *testing.T) {
	logger := testLogger()
	fw, err := firewall.NewFirewallWithRunner(
		config.FirewallConfig{Enabled: true, Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "hook {action} {mac} {ip} {port} {family} {proto}"}},
		config.FullBanConfig{}, "udp", logger,
		func(name string, args ...string) error { return nil },
	)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	blk := blocker.NewBlocker(fw, logger, false)
	defer blk.Close()

	blk.OnAlertStart("aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, "udp")
	deadline := time.Now().Add(2 * time.Second)
	for len(blk.Snapshot().Bans) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(blk.Snapshot().Bans) == 0 {
		t.Fatalf("封禁未生效")
	}

	srv, err := New(nil, blk, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, logger)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	h := srv.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/blocks", nil))
	var bs blocker.Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &bs); err != nil {
		t.Fatalf("解析 blocks 失败：%v", err)
	}
	if len(bs.Bans) != 1 {
		t.Fatalf("/blocks 应有 1 条封禁，got %d", len(bs.Bans))
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/unban",
		strings.NewReader(`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("/unban 状态码 %d", rr.Code)
	}
	var resp struct {
		Unbanned int `json:"unbanned"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 unban 失败：%v", err)
	}
	if resp.Unbanned != 1 {
		t.Fatalf("unbanned 应为 1，got %d", resp.Unbanned)
	}
}
