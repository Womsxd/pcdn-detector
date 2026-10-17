package minihttp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 差分测试：把同一段原始请求字节分别发给 minihttp 与标准库 net/http，
// 对比状态码 / 响应体 / 连接语义，用来发现「本实现与 net/http 行为不一致」的地方。
// 无法对齐的能力（chunked、体积上限等）以显式期望值记录，任何一侧行为变化都会让用例失败。

type diffResult struct {
	status int
	body   string
	close  bool
	hdr    http.Header
}

func echoMini(w *Response, r *Request) {
	w.Header().Set("X-Method", r.Method)
	w.Header().Set("X-Path", r.URL.Path)
	w.Header().Set("X-RawQuery", r.URL.RawQuery)
	w.Header().Set("X-Proto", r.Proto)
	w.Header().Set("X-Multi", strings.Join(r.Header.Values("X-Multi"), "|"))
	_, _ = fmt.Fprintf(w, "%s|%s|%s|%s|%s", r.Method, r.URL.Path, r.URL.RawQuery, r.Proto, r.Body)
}

func echoStd(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("X-Method", r.Method)
	w.Header().Set("X-Path", r.URL.Path)
	w.Header().Set("X-RawQuery", r.URL.RawQuery)
	w.Header().Set("X-Proto", r.Proto)
	w.Header().Set("X-Multi", strings.Join(r.Header.Values("X-Multi"), "|"))
	_, _ = fmt.Fprintf(w, "%s|%s|%s|%s|%s", r.Method, r.URL.Path, r.URL.RawQuery, r.Proto, body)
}

// startPair 以相同语义的处理器启动两套服务端，返回二者的地址。
func startPair(t *testing.T, miniTweak func(*Server)) (miniAddr, stdAddr string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mini 监听失败：%v", err)
	}
	ms := &Server{Handler: echoMini, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second}
	if miniTweak != nil {
		miniTweak(ms)
	}
	go func() { _ = ms.Serve(ln) }()
	t.Cleanup(func() { _ = ms.Close() })

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("std 监听失败：%v", err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(echoStd), ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = hs.Serve(ln2) }()
	t.Cleanup(func() { _ = hs.Close() })

	return ln.Addr().String(), ln2.Addr().String()
}

func rawRequest(t *testing.T, addr, raw string) diffResult {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接 %s 失败：%v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	// 用请求方法告知 ReadResponse 是否为 HEAD，否则 HEAD 响应会被当成有响应体去读。
	method, _, _ := strings.Cut(raw, " ")
	reqForRead, _ := http.NewRequest(strings.TrimSpace(method), "/", nil)
	resp, err := http.ReadResponse(bufio.NewReader(conn), reqForRead)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应体失败：%v", err)
	}
	return diffResult{status: resp.StatusCode, body: string(body), close: resp.Close, hdr: resp.Header}
}

func TestDifferentialParity(t *testing.T) {
	miniAddr, stdAddr := startPair(t, nil)

	cases := []struct {
		name  string
		raw   string
		note  string
		wantM int // 非 0 时表示这是有意差异，直接断言各自状态码
		wantS int
	}{
		{
			name: "简单 GET",
			raw:  "GET /a HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "查询串",
			raw:  "GET /a?x=1&y=%E4%B8%AD HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "百分号编码路径",
			raw:  "GET /a%20b HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "HTTP/1.0 默认短连接",
			raw:  "GET /a HTTP/1.0\r\n\r\n",
		},
		{
			name: "HTTP/1.0 keep-alive",
			raw:  "GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
		},
		{
			name: "HTTP/1.1 Connection close",
			raw:  "GET /a HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
		},
		{
			name: "重复同名头部",
			raw:  "GET /a HTTP/1.1\r\nHost: t\r\nX-Multi: 1\r\nX-Multi: 2\r\n\r\n",
		},
		{
			name: "头部名大小写无关",
			raw:  "GET /a HTTP/1.1\r\nHost: t\r\nx-mUlTi: v\r\n\r\n",
		},
		{
			name: "LF 行尾",
			raw:  "GET /a HTTP/1.1\nHost: t\n\n",
		},
		{
			name: "请求行前空行被拒绝",
			raw:  "\r\n\r\nGET /a HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "POST 定长请求体",
			raw:  "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello",
		},
		{
			name: "POST 空体",
			raw:  "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "HEAD 只回头",
			raw:  "HEAD /a HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "小写方法",
			raw:  "get /a HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "绝对形式 URI",
			raw:  "GET http://example.com/a?b=1 HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "垃圾请求行",
			raw:  "GARBAGE\r\n\r\n",
		},
		{
			name: "HTTP/1.1 缺少 Host",
			raw:  "GET /a HTTP/1.1\r\n\r\n",
		},
		{
			name: "Content-Length 非数字",
			raw:  "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: abc\r\n\r\n",
		},
		{
			name: "Content-Length 带正号",
			raw:  "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: +5\r\n\r\nhello",
		},
		{
			name: "Content-Length 相同重复",
			raw:  "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
		},
		{
			name: "Content-Length 冲突重复",
			raw:  "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
		},
		{
			name: "头部缺少冒号",
			raw:  "GET /a HTTP/1.1\r\nHost: t\r\nBroken\r\n\r\n",
		},
		{
			name: "请求行为空",
			raw:  "GET  HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "方法含非法字符",
			raw:  "G@T /a HTTP/1.1\r\nHost: t\r\n\r\n",
		},
		{
			name: "头部值含控制字符",
			raw:  "GET /a HTTP/1.1\r\nHost: t\r\nX-Bad: a\x00b\r\n\r\n",
		},
		{
			name:  "chunked 请求体（有意不支持）",
			raw:   "POST /a HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			note:  "minihttp 不实现 chunked 解码，返回 501；net/http 正常解码",
			wantM: StatusNotImplemented,
			wantS: http.StatusOK,
		},
		{
			name:  "请求头行超过 4KiB",
			raw:   "GET /a HTTP/1.1\r\nHost: t\r\nX-Long: " + strings.Repeat("y", 5000) + "\r\n\r\n",
			note:  "minihttp 单行上限 4KiB（设备内存约束），std 默认 1MiB",
			wantM: StatusRequestHeaderFieldsTooLarge,
			wantS: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := rawRequest(t, miniAddr, tc.raw)
			s := rawRequest(t, stdAddr, tc.raw)

			if tc.wantM != 0 || tc.wantS != 0 {
				if tc.wantM != 0 && m.status != tc.wantM {
					t.Fatalf("mini 状态码 %d，期望 %d（%s）", m.status, tc.wantM, tc.note)
				}
				if tc.wantS != 0 && s.status != tc.wantS {
					t.Fatalf("std 状态码 %d，期望 %d（%s）", s.status, tc.wantS, tc.note)
				}
				return
			}

			if m.status != s.status {
				t.Fatalf("状态码不一致：mini=%d std=%d", m.status, s.status)
			}
			if m.close != s.close {
				t.Fatalf("连接语义不一致：mini.close=%v std.close=%v", m.close, s.close)
			}
			// 协议层错误响应体只是给人看的（应用层错误体统一是 JSON），措辞不做对齐。
			if m.status >= 400 {
				return
			}
			if m.body != s.body {
				t.Fatalf("响应体不一致：\nmini=%q\nstd =%q", m.body, s.body)
			}
			for _, h := range []string{"Content-Length", "X-Method", "X-Path", "X-RawQuery", "X-Proto", "X-Multi"} {
				if got, want := m.hdr.Get(h), s.hdr.Get(h); got != want {
					t.Fatalf("响应头 %s 不一致：mini=%q std=%q", h, got, want)
				}
			}
		})
	}
}

// TestDifferentialChunkedBodyLimits 单独用 8 字节上限启动一对服务端，避免影响其它用例。
func TestDifferentialChunkedBodyLimits(t *testing.T) {
	miniAddr, stdAddr := startPair(t, func(s *Server) { s.MaxBodyBytes = 8 })
	_ = stdAddr

	// 正好等于上限：应放行。
	m := rawRequest(t, miniAddr, "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 8\r\n\r\n12345678")
	if m.status != StatusOK || !strings.HasSuffix(m.body, "12345678") {
		t.Fatalf("等于上限时不应拒绝：status=%d body=%q", m.status, m.body)
	}

	// 超过上限：413。
	m = rawRequest(t, miniAddr, "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 9\r\n\r\n123456789")
	if m.status != StatusRequestEntityTooLarge {
		t.Fatalf("超过上限应 413，got %d", m.status)
	}

	// Content-Length 溢出 int64。
	m = rawRequest(t, miniAddr, "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 99999999999999999999\r\n\r\n")
	if m.status != StatusBadRequest {
		t.Fatalf("溢出应 400，got %d", m.status)
	}
}

// 流水线（同一次写入两个请求）应依次得到两个响应。
func TestDifferentialPipelining(t *testing.T) {
	miniAddr, stdAddr := startPair(t, nil)

	for _, addr := range []string{miniAddr, stdAddr} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("连接失败：%v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		raw := "GET /first HTTP/1.1\r\nHost: t\r\n\r\nGET /second HTTP/1.1\r\nHost: t\r\n\r\n"
		if _, err := io.WriteString(conn, raw); err != nil {
			t.Fatalf("写请求失败：%v", err)
		}
		br := bufio.NewReader(conn)
		for _, want := range []string{"/first", "/second"} {
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("%s: 读响应失败：%v", addr, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("X-Path") != want {
				t.Fatalf("%s: 流水线响应不符：%d %q", addr, resp.StatusCode, body)
			}
		}
		conn.Close()
	}
}

// 处理器不读取请求体时，连接仍应保持同步（minihttp 在调用处理器前已读完定长体）。
func TestDifferentialUnreadBodyKeepAlive(t *testing.T) {
	quietMini := func(w *Response, r *Request) { _, _ = w.Write([]byte("ok")) }
	quietStd := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ms := &Server{Handler: quietMini, IdleTimeout: 2 * time.Second}
	go func() { _ = ms.Serve(ln) }()
	t.Cleanup(func() { _ = ms.Close() })

	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	hs := &http.Server{Handler: http.HandlerFunc(quietStd)}
	go func() { _ = hs.Serve(ln2) }()
	t.Cleanup(func() { _ = hs.Close() })

	for _, addr := range []string{ln.Addr().String(), ln2.Addr().String()} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("连接失败：%v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		raw := "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello" +
			"GET /b HTTP/1.1\r\nHost: t\r\n\r\n"
		if _, err := io.WriteString(conn, raw); err != nil {
			t.Fatalf("写请求失败：%v", err)
		}
		br := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("%s: 第 %d 个响应读取失败：%v", addr, i+1, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || string(body) != "ok" {
				t.Fatalf("%s: 第 %d 个响应不符：%d %q", addr, i+1, resp.StatusCode, body)
			}
		}
		conn.Close()
	}
}

// 记录与 net/http 的已知形态差异，避免以后误以为是 bug 或悄悄变化。
func TestDifferentialKnownShapeDifference(t *testing.T) {
	miniAddr, stdAddr := startPair(t, nil)

	m := rawRequest(t, miniAddr, "GET /a HTTP/1.1\r\nHost: t\r\n\r\n")
	s := rawRequest(t, stdAddr, "GET /a HTTP/1.1\r\nHost: t\r\n\r\n")

	// 两侧都应带合法的 Date（IMF-fixdate），minihttp 手写格式化也必须是标准格式。
	for name, h := range map[string]diffResult{"mini": m, "std": s} {
		v := h.hdr.Get("Date")
		if v == "" {
			t.Fatalf("%s 应写 Date 头", name)
		}
		ts, err := http.ParseTime(v)
		if err != nil {
			t.Fatalf("%s 的 Date 格式非法：%q（%v）", name, v, err)
		}
		if d := time.Since(ts); d < -time.Minute || d > time.Minute {
			t.Fatalf("%s 的 Date 偏差过大：%v", name, d)
		}
	}
	// 未显式设置 Content-Type 但有响应体时，两侧都补 text/plain。
	if got, want := m.hdr.Get("Content-Type"), s.hdr.Get("Content-Type"); got != want {
		t.Fatalf("Content-Type 不一致：mini=%q std=%q", got, want)
	}
	if m.status != s.status || m.body != s.body {
		t.Fatalf("基本响应应一致：mini=%d/%q std=%d/%q", m.status, m.body, s.status, s.body)
	}
}

// ErrorHandler 注入后，协议级错误应使用注入的格式（本项目实际注入 JSON）。
func TestProtocolErrorHandler(t *testing.T) {
	_, addr := startServer(t, okHandler, func(s *Server) {
		s.ErrorHandler = func(w *Response, code int, msg string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"code":%d,"error":%q}`, code, msg)
		}
	})

	for _, raw := range []string{"GARBAGE\r\n\r\n", "GET /a HTTP/1.1\r\n\r\n"} {
		conn := dial(t, addr)
		if _, err := io.WriteString(conn, raw); err != nil {
			t.Fatalf("写请求失败：%v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("读响应失败：%v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != StatusBadRequest {
			t.Fatalf("应 400，got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type 未使用注入值：%q", ct)
		}
		if !strings.HasPrefix(string(body), `{"code":400,`) {
			t.Fatalf("错误体未使用注入格式：%q", body)
		}
	}
}

// 默认（未注入 ErrorHandler）协议级错误是 text/plain，且 Date 仍应存在。
func TestProtocolErrorDefault(t *testing.T) {
	_, addr := startServer(t, okHandler, nil)
	conn := dial(t, addr)
	if _, err := io.WriteString(conn, "GARBAGE\r\n\r\n"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("默认应为 text/plain，got %q", ct)
	}
	if _, err := http.ParseTime(resp.Header.Get("Date")); err != nil {
		t.Fatalf("错误响应也应带合法 Date：%q", resp.Header.Get("Date"))
	}
}
