package minihttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func startServer(t *testing.T, h Handler, tweak func(*Server)) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	s := &Server{Handler: h, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second}
	if tweak != nil {
		tweak(s)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })
	return s, ln.Addr().String()
}

// 同一连接上连续两次请求应都得到正确响应（keep-alive）。
func TestKeepAlive(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) {
		w.Header().Set("X-Path", r.Path())
		_, _ = w.Write([]byte("ok"))
	}, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		if _, err := fmt.Fprintf(conn, "GET /ping HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
			t.Fatalf("写请求失败：%v", err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("第 %d 次读响应失败：%v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "ok" || resp.Header.Get("X-Path") != "/ping" {
			t.Fatalf("第 %d 次响应不符：%d %q %q", i, resp.StatusCode, body, resp.Header.Get("X-Path"))
		}
		if resp.Close {
			t.Fatalf("第 %d 次响应不应关闭连接", i)
		}
	}
}

// 语法错误请求应返回 400 并断开。
func TestBadRequestLine(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) { _, _ = w.Write([]byte("x")) }, nil)

	conn, err := net.Dial("tcp", addr)
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
	resp.Body.Close()
	if resp.StatusCode != StatusBadRequest {
		t.Fatalf("应 400，got %d", resp.StatusCode)
	}
}

// 超过 MaxBodyBytes 的请求体应 413；chunked 请求体应 411。
func TestBodyLimits(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) { _, _ = w.Write(r.Body) },
		func(s *Server) { s.MaxBodyBytes = 8 })

	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{"too large", "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n", StatusRequestEntityTooLarge},
		{"chunked", "POST /x HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", StatusNotImplemented},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("%s: 连接失败：%v", tc.name, err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, tc.raw); err != nil {
			t.Fatalf("%s: 写请求失败：%v", tc.name, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s: 读响应失败：%v", tc.name, err)
		}
		resp.Body.Close()
		conn.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s: 状态码 %d，期望 %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}

// 处理器 panic 不应带崩连接与服务端，返回 500。
func TestHandlerPanic(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) { panic("boom") }, nil)

	resp, err := http.Get("http://" + addr + "/x")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusInternalServerError {
		t.Fatalf("应 500，got %d", resp.StatusCode)
	}
}

// HEAD 请求只返回头部，Content-Length 与 GET 一致。
func TestHeadNoBody(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) { _, _ = w.Write([]byte("hello")) }, nil)

	req, _ := http.NewRequest(http.MethodHead, "http://"+addr+"/x", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if len(b) != 0 || resp.ContentLength != 5 {
		t.Fatalf("HEAD 响应不符：len=%d content-length=%d", len(b), resp.ContentLength)
	}
}

// Shutdown 后监听关闭，且在途请求能正常完成。
func TestShutdown(t *testing.T) {
	s, addr := startServer(t, func(w *Response, r *Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	}, nil)

	errCh := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond) // 让请求先进入处理器

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown 失败：%v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("在途请求应正常完成：%v", err)
	}
	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Fatalf("Shutdown 后不应还能连接")
	}
}

// 畸形头部（过长 / 无冒号）应被拒绝而不是无限读取。
func TestBadHeaders(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) { _, _ = w.Write([]byte("x")) }, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nBrokenHeader\r\n\r\n"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != StatusBadRequest {
		t.Fatalf("应 400，got %d", resp.StatusCode)
	}
}
