package httpapi

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/logx"
	"pcdn-detect/internal/netutil"
)

func testLogger() *logx.Logger { return logx.New(io.Discard, "", 0) }

func newTestDetector() *detector.Detector {
	return detector.NewDetector(20, time.Minute, 10*time.Minute, nil, testLogger(), false, false, 1000, 0)
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

func boolPtr(v bool) *bool { return &v }

// testServer 在随机端口上启动真实监听，通过标准库客户端验证（标准库仅进测试二进制）。
type testServer struct {
	base   string
	client *http.Client
}

func start(t *testing.T, srv *Server) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	ms := srv.transport() // 与生产一致：同样的超时、错误体渲染策略
	ms.Addr = ""
	go func() { _ = ms.Serve(ln) }()
	t.Cleanup(func() { _ = ms.Close() })
	return &testServer{base: "http://" + ln.Addr().String(), client: &http.Client{Timeout: 5 * time.Second}}
}

func (ts *testServer) do(t *testing.T, method, path, body string, hdr map[string]string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.base+path, rdr)
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
	return resp.StatusCode, b
}

// 非回环地址 + 空 token 应拒绝构建。
func TestNewRejectsNonLoopbackWithoutToken(t *testing.T) {
	_, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "0.0.0.0:8080"}, nil, testLogger())
	if err == nil {
		t.Fatalf("非回环地址且无 token 时应报错")
	}
	// 回环地址无需 token。
	if _, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "127.0.0.1:8080"}, nil, testLogger()); err != nil {
		t.Fatalf("回环地址不应报错：%v", err)
	}
	// 非回环 + token 允许。
	if _, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "0.0.0.0:8080", Token: "x"}, nil, testLogger()); err != nil {
		t.Fatalf("非回环 + token 不应报错：%v", err)
	}
}

// token = "allow-no-token" 应允许非回环绑定且不校验鉴权。
func TestAllowNoToken(t *testing.T) {
	srv, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "0.0.0.0:8080", Token: config.TokenAllowNoToken}, nil, testLogger())
	if err != nil {
		t.Fatalf("allow-no-token 应允许非回环绑定：%v", err)
	}
	ts := start(t, srv)
	if code, _ := ts.do(t, http.MethodGet, "/api/v1/health", "", nil); code != http.StatusOK {
		t.Fatalf("allow-no-token 下无 token 应放行，got %d", code)
	}
}

// Bearer 鉴权：缺失 / 错误 401，正确 200。
func TestAuth(t *testing.T) {
	srv, err := New(newTestDetector(), nil, config.HTTPConfig{Listen: "127.0.0.1:8080", Token: "s3cr3t"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong", "Bearer nope", http.StatusUnauthorized},
		{"ok", "Bearer s3cr3t", http.StatusOK},
	} {
		var hdr map[string]string
		if tc.header != "" {
			hdr = map[string]string{"Authorization": tc.header}
		}
		if code, _ := ts.do(t, http.MethodGet, "/api/v1/health", "", hdr); code != tc.want {
			t.Errorf("%s: 状态码 %d，期望 %d", tc.name, code, tc.want)
		}
	}
}

// /devices 只返回统计信息，/peers 按需返回对端 IP 列表并受 device_ip_limit 约束。
func TestDevicesAndPeersIPLimit(t *testing.T) {
	det := newTestDetector()
	for i := 0; i < 5; i++ {
		observe(det, "aa:bb:cc:dd:ee:ff", 40000, netip.AddrFrom4([4]byte{1, 1, 1, byte(i + 1)}).String())
	}
	srv, err := New(det, nil, config.HTTPConfig{Listen: "127.0.0.1:8080", DeviceIPLimit: intPtr(3)}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	code, body := ts.do(t, http.MethodGet, "/api/v1/devices", "", nil)
	if code != http.StatusOK {
		t.Fatalf("状态码 %d", code)
	}
	var snap devicesView
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(snap.Devices) != 1 || snap.Devices[0].IPv4.Ports != 1 || snap.Devices[0].IPv6.Ports != 0 {
		t.Fatalf("设备端口统计不符：%+v", snap)
	}
	if v4 := snap.Devices[0].IPv4; v4.UDP != (viewProto{Ports: 1}) || v4.TCP != (viewProto{}) {
		t.Fatalf("IPv4 协议拆分不符：%+v", v4)
	}
	if snap.Devices[0].IPv4.Banned != 0 {
		t.Fatalf("无防火墙时封禁数应为 0：%+v", snap.Devices[0])
	}
	if strings.Contains(string(body), "peer_ips") || strings.Contains(string(body), "alerting") {
		t.Fatalf("/devices 不应返回端口明细：%s", body)
	}

	// /peers 默认按 device_ip_limit 截断并标记 truncated。
	peersURL := "/api/v1/peers?mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&port=40000&proto=udp"
	code, body = ts.do(t, http.MethodGet, peersURL, "", nil)
	if code != http.StatusOK {
		t.Fatalf("/peers 状态码 %d：%s", code, body)
	}
	var pv detector.PeerView
	if err := json.Unmarshal(body, &pv); err != nil {
		t.Fatalf("解析 peers 失败：%v", err)
	}
	if !pv.Truncated || len(pv.PeerIPs) != 3 || pv.PeerCount != 5 {
		t.Fatalf("截断不符：truncated=%v len=%d count=%d", pv.Truncated, len(pv.PeerIPs), pv.PeerCount)
	}

	// limit 只能把上限调小。
	code, body = ts.do(t, http.MethodGet, peersURL+"&limit=2", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/peers?limit=2 状态码 %d：%s", code, body)
	}
	if err := json.Unmarshal(body, &pv); err != nil {
		t.Fatalf("解析 peers 失败：%v", err)
	}
	if !pv.Truncated || len(pv.PeerIPs) != 2 {
		t.Fatalf("limit=2 应返回 2 个 IP，got %d（truncated=%v）", len(pv.PeerIPs), pv.Truncated)
	}

	// 分页：page 基于生效的 limit 计算偏移，truncated 表示本页之后还有对端。
	var pvs peersView
	for _, tc := range []struct {
		query   string
		page    int64
		limit   int
		wantIPs []string
		trunc   bool
	}{
		{"&page=2", 2, 3, []string{"1.1.1.4", "1.1.1.5"}, false},
		{"&limit=2&page=2", 2, 2, []string{"1.1.1.3", "1.1.1.4"}, true},
		{"&limit=2&page=3", 3, 2, []string{"1.1.1.5"}, false},
		{"&limit=2&page=4", 4, 2, nil, false},
	} {
		code, body = ts.do(t, http.MethodGet, peersURL+tc.query, "", nil)
		if code != http.StatusOK {
			t.Fatalf("/peers%s 状态码 %d：%s", tc.query, code, body)
		}
		if err := json.Unmarshal(body, &pvs); err != nil {
			t.Fatalf("解析 peers 失败：%v", err)
		}
		if pvs.Page != tc.page || pvs.Limit != tc.limit || pvs.PeerCount != 5 ||
			pvs.Truncated != tc.trunc || len(pvs.PeerIPs) != len(tc.wantIPs) {
			t.Fatalf("/peers%s 分页不符：%+v", tc.query, pvs)
		}
		for i := range tc.wantIPs {
			if pvs.PeerIPs[i] != tc.wantIPs[i] {
				t.Fatalf("/peers%s 第 %d 个 IP 应为 %s，got %s", tc.query, i+1, tc.wantIPs[i], pvs.PeerIPs[i])
			}
		}
	}
	for _, q := range []string{"&page=0", "&page=-1", "&page=abc"} {
		if code, _ := ts.do(t, http.MethodGet, peersURL+q, "", nil); code != http.StatusBadRequest {
			t.Fatalf("/peers%s 应返回 400，got %d", q, code)
		}
	}

	// 未跟踪的设备 / 端口返回 404。
	code, _ = ts.do(t, http.MethodGet, "/api/v1/peers?mac=aa%3Abb%3Acc%3Add%3Aee%3A00&port=40000", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("未跟踪设备应返回 404，got %d", code)
	}
}

// /device 返回单设备端口明细：ipv4 / ipv6 统计始终为全量口径，
// ports / matched 受 family / state / limit 筛选影响。
func TestDeviceDetailFilters(t *testing.T) {
	logger := testLogger()
	det := detector.NewDetector(10, time.Minute, time.Hour, nil, logger, false, false, 0, 0)
	const macStr = "aa:bb:cc:dd:ee:ff"
	mac, _ := netutil.ParseMAC(macStr)
	now := time.Now()
	observePort := func(port uint16, proto uint8, v6 bool) {
		ip, remote := "192.168.1.2", "1.1.1.1"
		if v6 {
			ip, remote = "2408:8240:9411:37b0::1", "2001:db8::1"
		}
		det.Observe(detector.Observation{
			MAC: mac, IP: netip.MustParseAddr(ip), LocalPort: port,
			RemoteIP: netip.MustParseAddr(remote), Up: true, V6: v6,
			Proto: proto, Length: 100, TS: now,
		})
	}
	observePort(40000, netutil.ProtoUDP, false) // 会被封禁
	observePort(40001, netutil.ProtoUDP, false)
	observePort(40002, netutil.ProtoTCP, false)
	observePort(40000, netutil.ProtoUDP, true)
	observePort(40003, netutil.ProtoUDP, true)

	// ban_both=false：v4 触发的封禁只影响 v4，便于验证按地址族统计。
	fw, err := firewall.NewFirewallWithRunner(
		config.FirewallConfig{
			Enabled: true,
			Backend: "hook",
			BanBoth: boolPtr(false),
			Hook:    config.FirewallHookConfig{Cmd: "hook {action} {mac} {port} {family}"},
		},
		config.FullBanConfig{}, config.ProtoModeUDP, logger,
		func(string, ...string) error { return nil },
	)
	if err != nil {
		t.Fatalf("构建防火墙失败：%v", err)
	}
	blk := blocker.NewBlocker(fw, logger, false)
	defer blk.Close()
	blk.OnAlertStart(macStr, "192.168.1.2", 40000, "udp")
	deadline := time.Now().Add(2 * time.Second)
	for len(blk.BanIndex().Rules) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	srv, err := New(det, blk, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, logger)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	get := func(t *testing.T, query string) deviceDetailView {
		t.Helper()
		code, body := ts.do(t, http.MethodGet, "/api/v1/device?mac="+macStr+query, "", nil)
		if code != http.StatusOK {
			t.Fatalf("/device%s 状态码 %d：%s", query, code, body)
		}
		var v deviceDetailView
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("解析 device 失败：%v", err)
		}
		return v
	}

	wantV4 := viewFamily{Ports: 3, Banned: 1, UDP: viewProto{Ports: 2, Banned: 1}, TCP: viewProto{Ports: 1}}
	wantV6 := viewFamily{Ports: 2, UDP: viewProto{Ports: 2}}

	all := get(t, "")
	if all.IPv4 != wantV4 || all.IPv6 != wantV6 {
		t.Fatalf("全量统计不符：%+v", all)
	}
	if all.Matched != 5 || len(all.Ports) != 5 || all.Truncated || all.FullBanned {
		t.Fatalf("全量明细不符：%+v", all)
	}
	if all.Page != 1 || all.Limit != defaultDevicePortLimit {
		t.Fatalf("默认分页参数不符：page=%d limit=%d", all.Page, all.Limit)
	}

	// family 只筛选明细，不影响统计。
	if v4 := get(t, "&family=v4"); v4.Matched != 3 || len(v4.Ports) != 3 || v4.IPv6.Ports != 2 {
		t.Fatalf("family=v4 不符：%+v", v4)
	}
	if v6 := get(t, "&family=ipv6"); v6.Matched != 2 || len(v6.Ports) != 2 || v6.IPv4.Ports != 3 {
		t.Fatalf("family=ipv6 不符：%+v", v6)
	}

	banned := get(t, "&state=banned")
	if banned.Matched != 1 || len(banned.Ports) != 1 {
		t.Fatalf("state=banned 不符：%+v", banned)
	}
	if p := banned.Ports[0]; p.Port != 40000 || p.V6 || !p.Banned || p.Proto != "udp" {
		t.Fatalf("封禁条目不符：%+v", p)
	}
	if unbanned := get(t, "&family=v4&state=unbanned"); unbanned.Matched != 2 || len(unbanned.Ports) != 2 {
		t.Fatalf("family=v4&state=unbanned 不符：%+v", unbanned)
	}

	// 端口明细字段应内联输出，而不是嵌套在 PortView 之下。
	_, raw := ts.do(t, http.MethodGet, "/api/v1/device?mac="+macStr+"&state=banned", "", nil)
	if !strings.Contains(string(raw), `"port":40000`) || !strings.Contains(string(raw), `"banned":true`) ||
		strings.Contains(string(raw), "PortView") {
		t.Fatalf("端口明细 JSON 不符：%s", raw)
	}

	limited := get(t, "&limit=2")
	if limited.Matched != 5 || len(limited.Ports) != 2 || !limited.Truncated {
		t.Fatalf("limit=2 应在截断前统计 matched=5：%+v", limited)
	}

	// 分页：matched 为筛选后的总数，page 从 1 开始，truncated 表示本页之后还有条目。
	page2 := get(t, "&limit=2&page=2")
	if page2.Page != 2 || page2.Limit != 2 || page2.Matched != 5 || len(page2.Ports) != 2 || !page2.Truncated {
		t.Fatalf("limit=2&page=2 不符：%+v", page2)
	}
	if page2.Ports[0].Port != 40001 || page2.Ports[1].Port != 40002 {
		t.Fatalf("第二页应为 40001 / 40002：%+v", page2.Ports)
	}
	page3 := get(t, "&limit=2&page=3")
	if page3.Matched != 5 || len(page3.Ports) != 1 || page3.Ports[0].Port != 40003 || page3.Truncated {
		t.Fatalf("末页不符：%+v", page3)
	}
	emptyPage := get(t, "&limit=2&page=4")
	if emptyPage.Matched != 5 || len(emptyPage.Ports) != 0 || emptyPage.Truncated {
		t.Fatalf("越界页应返回空列表且 truncated=false：%+v", emptyPage)
	}
	bannedPage2 := get(t, "&state=banned&limit=1&page=2")
	if bannedPage2.Matched != 1 || len(bannedPage2.Ports) != 0 || bannedPage2.Truncated {
		t.Fatalf("筛选后越界页不符：%+v", bannedPage2)
	}

	// /devices 只返回设备级统计，且与 /device 的全量口径一致。
	code, body := ts.do(t, http.MethodGet, "/api/v1/devices", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/devices 状态码 %d", code)
	}
	var devs devicesView
	if err := json.Unmarshal(body, &devs); err != nil {
		t.Fatalf("解析 devices 失败：%v", err)
	}
	if len(devs.Devices) != 1 || devs.Devices[0].IPv4 != wantV4 || devs.Devices[0].IPv6 != wantV6 {
		t.Fatalf("/devices 统计不符：%+v", devs)
	}
	if !strings.Contains(string(body), `"udp":{"ports":2,"banned":1}`) ||
		!strings.Contains(string(body), `"tcp":{"ports":1,"banned":0}`) {
		t.Fatalf("/devices 缺少 udp / tcp 协议拆分：%s", body)
	}

	// 参数校验与未跟踪设备。
	for _, q := range []string{"&family=foo", "&state=foo", "&limit=0", "&limit=-1", "&limit=x", "&page=0", "&page=-1", "&page=abc"} {
		if code, _ := ts.do(t, http.MethodGet, "/api/v1/device?mac="+macStr+q, "", nil); code != http.StatusBadRequest {
			t.Fatalf("%s 应返回 400，got %d", q, code)
		}
	}
	if code, _ := ts.do(t, http.MethodGet, "/api/v1/device", "", nil); code != http.StatusBadRequest {
		t.Fatalf("缺少 mac 应返回 400，got %d", code)
	}
	if code, _ := ts.do(t, http.MethodGet, "/api/v1/device?mac=11:22:33:44:55:66", "", nil); code != http.StatusNotFound {
		t.Fatalf("未跟踪设备应返回 404，got %d", code)
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
	ts := start(t, srv)

	code, body := ts.do(t, http.MethodGet, "/api/v1/status", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/status 状态码 %d", code)
	}
	var st statusView
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("解析 status 失败：%v", err)
	}
	if st.Status != "ok" || st.TrackedDevices != 1 {
		t.Fatalf("status 不符：%+v", st)
	}

	code, body = ts.do(t, http.MethodGet, "/dev/memory", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/dev/memory 状态码 %d", code)
	}
	var mv memoryView
	if err := json.Unmarshal(body, &mv); err != nil {
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
	ts := start(t, srv)

	code, body := ts.do(t, http.MethodGet, "/api/v1/blocks", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/blocks 状态码 %d", code)
	}
	var empty blocker.Snapshot
	if err := json.Unmarshal(body, &empty); err != nil {
		t.Fatalf("/blocks 应返回合法 JSON：%v", err)
	}
	if len(empty.Bans) != 0 {
		t.Fatalf("/blocks 无防火墙时应为空，got %+v", empty)
	}

	code, _ = ts.do(t, http.MethodPost, "/api/v1/unban",
		`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}`, nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/unban 无防火墙应 503，got %d", code)
	}
}

// SetBlocker 热更新：reload 启停防火墙后，HTTP 层应看到新的 Blocker 而非启动时的旧指针。
func TestSetBlockerHotSwap(t *testing.T) {
	logger := testLogger()
	srv, err := New(newTestDetector(), nil, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, logger)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	// 初始无防火墙：/unban 应 503。
	if code, _ := ts.do(t, http.MethodPost, "/api/v1/unban",
		`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}`, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("/unban 无防火墙应 503，got %d", code)
	}

	// reload 启用防火墙：设置新 blocker 后，/blocks 应能看到其状态。
	fw, err := firewall.NewFirewallWithRunner(
		config.FirewallConfig{Enabled: true, Backend: "hook", Hook: config.FirewallHookConfig{Cmd: "hook {action} {mac} {port}"}},
		config.FullBanConfig{}, "udp", logger,
		func(string, ...string) error { return nil },
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
	srv.SetBlocker(blk)

	_, body := ts.do(t, http.MethodGet, "/api/v1/blocks", "", nil)
	var bs blocker.Snapshot
	if err := json.Unmarshal(body, &bs); err != nil {
		t.Fatalf("解析 blocks 失败：%v", err)
	}
	if len(bs.Bans) != 1 {
		t.Fatalf("/blocks 应看到新 blocker 的 1 条封禁，got %d", len(bs.Bans))
	}

	// /status 只取计数，数值应与 /blocks 一致。
	_, body = ts.do(t, http.MethodGet, "/api/v1/status", "", nil)
	var st statusView
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("解析 status 失败：%v", err)
	}
	if st.ActiveBans != len(bs.Bans) {
		t.Fatalf("/status 的 active_bans 应为 %d，got %d", len(bs.Bans), st.ActiveBans)
	}

	// reload 关闭防火墙：/unban 恢复 503。
	srv.SetBlocker(nil)
	if code, _ := ts.do(t, http.MethodPost, "/api/v1/unban",
		`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}`, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("/unban 关闭防火墙后应 503，got %d", code)
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
	ts := start(t, srv)
	code, body := ts.do(t, http.MethodPost, "/api/v1/reload", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/reload 状态码 %d", code)
	}
	if !called {
		t.Fatalf("ReloadFunc 未被调用")
	}
	var res ReloadResult
	if err := json.Unmarshal(body, &res); err != nil {
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
	ts := start(t, srv)

	_, body := ts.do(t, http.MethodGet, "/api/v1/blocks", "", nil)
	var bs blocker.Snapshot
	if err := json.Unmarshal(body, &bs); err != nil {
		t.Fatalf("解析 blocks 失败：%v", err)
	}
	if len(bs.Bans) != 1 {
		t.Fatalf("/blocks 应有 1 条封禁，got %d", len(bs.Bans))
	}

	code, body := ts.do(t, http.MethodPost, "/api/v1/unban",
		`{"mac":"aa:bb:cc:dd:ee:ff","port":40000,"proto":"udp"}`, nil)
	if code != http.StatusOK {
		t.Fatalf("/unban 状态码 %d", code)
	}
	var resp struct {
		Unbanned int `json:"unbanned"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("解析 unban 失败：%v", err)
	}
	if resp.Unbanned != 1 {
		t.Fatalf("unbanned 应为 1，got %d", resp.Unbanned)
	}
}

// 路由语义：未知路径 404、方法不允许 405（带 Allow 头）、HEAD 只回头、坏 JSON 400。
func TestRouting(t *testing.T) {
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

	srv, err := New(newTestDetector(), blk, config.HTTPConfig{Listen: "127.0.0.1:8080"}, nil, logger)
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	if code, _ := ts.do(t, http.MethodGet, "/api/v1/nope", "", nil); code != http.StatusNotFound {
		t.Fatalf("未知路径应 404，got %d", code)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.base+"/api/v1/unban", nil)
	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("方法不允许应 405，got %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "POST" {
		t.Fatalf("Allow 头不符：%q", allow)
	}

	code, body := ts.do(t, http.MethodHead, "/api/v1/health", "", nil)
	if code != http.StatusOK || len(body) != 0 {
		t.Fatalf("HEAD 应 200 且无响应体，got %d len=%d", code, len(body))
	}

	// 请求体不合法（非法 JSON 或空体）应 400，且服务端保持可用。
	if code, _ := ts.do(t, http.MethodPost, "/api/v1/unban", "{", nil); code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应 400，got %d", code)
	}
	if code, _ := ts.do(t, http.MethodGet, "/api/v1/health", "", nil); code != http.StatusOK {
		t.Fatalf("错误请求后服务不可用，got %d", code)
	}
}

// 协议级错误（请求行非法）也应返回统一 JSON 错误体，并带合法的 Date 头。
func TestProtocolErrorIsJSON(t *testing.T) {
	srv, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "127.0.0.1:8080"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	ts := start(t, srv)

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.base, "http://"))
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GARBAGE\r\n\r\n"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("应 400，got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("协议级错误也应为 JSON，got %q", ct)
	}
	if resp.Header.Get("Date") == "" {
		t.Fatalf("响应缺少 Date 头")
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("错误体不是合法 JSON：%v", err)
	}
	if body.Error == "" {
		t.Fatalf("错误体缺少 error 字段")
	}
}

// /dev/memory 只读取 main 记录的运行时参数：不得改写 GC 百分比与堆软上限。
// （原实现用 debug.SetMemoryLimit(-1) 读数，会把 memory_limit 静默改成「不限制」。）
func TestMemoryHandlerKeepsRuntimeSettings(t *testing.T) {
	prevGC := debug.SetGCPercent(37)
	defer debug.SetGCPercent(prevGC)
	prevLimit := debug.SetMemoryLimit(1 << 30)
	defer debug.SetMemoryLimit(prevLimit)

	srv, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "127.0.0.1:8080"}, nil, testLogger())
	if err != nil {
		t.Fatalf("构建失败：%v", err)
	}
	srv.SetRuntimeLimits(37, 1<<30)
	ts := start(t, srv)

	code, body := ts.do(t, http.MethodGet, "/dev/memory", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/dev/memory 状态码 %d", code)
	}
	var v memoryView
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("解析响应失败：%v", err)
	}
	if v.GCPercent != 37 || v.GOMEMLIMITBytes != 1<<30 {
		t.Fatalf("应返回记录的运行时参数，got gc_percent=%d gomemlimit=%d", v.GCPercent, v.GOMEMLIMITBytes)
	}

	// 读回运行时设置（读取后立即恢复），确认接口未改写它们。
	if got := debug.SetGCPercent(-1); got != 37 {
		debug.SetGCPercent(got)
		t.Fatalf("gc_percent 被接口改写为 %d", got)
	} else {
		debug.SetGCPercent(got)
	}
	if got := debug.SetMemoryLimit(-1); got != 1<<30 {
		debug.SetMemoryLimit(got)
		t.Fatalf("堆软上限被接口改写为 %d", got)
	} else {
		debug.SetMemoryLimit(got)
	}
}
