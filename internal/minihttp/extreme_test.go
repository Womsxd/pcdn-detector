package minihttp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func okHandler(w *Response, r *Request) { _, _ = w.Write([]byte("ok")) }

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// 慢速请求头（slowloris）：超过 ReadHeaderTimeout 应被断开，不占住连接。
func TestSlowHeaderTimeout(t *testing.T) {
	_, addr := startServer(t, okHandler, func(s *Server) { s.ReadHeaderTimeout = 150 * time.Millisecond })
	c := dial(t, addr)
	if _, err := io.WriteString(c, "GET /x HTTP/1.1\r\nHost: t\r\nX-Slow: "); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	time.Sleep(400 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(c).ReadByte(); err == nil {
		t.Fatalf("超过 ReadHeaderTimeout 后连接应被关闭")
	}
}

// 空闲 keep-alive 连接超过 IdleTimeout 应被回收。
func TestIdleKeepAliveTimeout(t *testing.T) {
	_, addr := startServer(t, okHandler, func(s *Server) {
		s.ReadHeaderTimeout = time.Second
		s.IdleTimeout = 150 * time.Millisecond
	})
	c := dial(t, addr)
	if _, err := io.WriteString(c, "GET /a HTTP/1.1\r\nHost: t\r\n\r\n"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(400 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatalf("空闲超时后连接应被关闭")
	}
}

// 单连接上大量连续请求：不应出现状态错乱 / 句柄泄漏。
func TestManySequentialRequests(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) {
		_, _ = w.Write([]byte(r.Path()))
	}, nil)

	c := dial(t, addr)
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	const n = 500
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("/req-%d", i)
		if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: t\r\n\r\n", path); err != nil {
			t.Fatalf("第 %d 次写请求失败：%v", i, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("第 %d 次读响应失败：%v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != path {
			t.Fatalf("第 %d 次响应不符：%d %q", i, resp.StatusCode, body)
		}
	}
}

// 大于 bufio 缓冲（4KiB）的响应体应完整写出。
func TestLargeResponse(t *testing.T) {
	payload := strings.Repeat("A", 256<<10)
	_, addr := startServer(t, func(w *Response, r *Request) { _, _ = io.WriteString(w, payload) }, nil)

	resp, err := http.Get("http://" + addr + "/big")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败：%v", err)
	}
	if len(body) != len(payload) || resp.ContentLength != int64(len(payload)) {
		t.Fatalf("响应体不完整：len=%d content-length=%d", len(body), resp.ContentLength)
	}
}

// 并发连接：多客户端同时读写，结果全部正确。
func TestConcurrentClients(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) {
		_, _ = w.Write([]byte("ok"))
	}, nil)

	const workers, perWorker = 32, 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				resp, err := client.Get(fmt.Sprintf("http://%s/w-%d-%d", addr, id, j))
				if err != nil {
					errCh <- err
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(body) != "ok" {
					errCh <- fmt.Errorf("状态 %d body %q", resp.StatusCode, body)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发请求失败：%v", err)
	}
}

// 大量空闲连接下 Shutdown 应尽快返回（靠读超时唤醒，而不是等 IdleTimeout）。
func TestShutdownClosesIdleConnsFast(t *testing.T) {
	s, addr := startServer(t, okHandler, func(s *Server) { s.IdleTimeout = 30 * time.Second })

	conns := make([]net.Conn, 0, 20)
	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("连接失败：%v", err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	time.Sleep(50 * time.Millisecond) // 让连接进入读取等待

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown 失败：%v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("空闲连接下 Shutdown 用时过长：%v", d)
	}
}

// 处理器卡住时，Shutdown 应在 ctx 超时后返回错误，而不是永久阻塞。
func TestShutdownTimeoutWithHangingHandler(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	s, addr := startServer(t, func(w *Response, r *Request) { <-release }, nil)
	c := dial(t, addr)
	if _, err := io.WriteString(c, "GET /hang HTTP/1.1\r\nHost: t\r\n\r\n"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.Shutdown(ctx)
	if err == nil {
		t.Fatalf("处理器卡住时 Shutdown 应超时返回")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Shutdown 超时后返回过慢：%v", d)
	}
}

// 客户端读到一半断开：服务端不应崩溃，后续请求仍正常。
func TestAbruptClientDisconnect(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) {
		_, _ = w.Write(bytes.Repeat([]byte("B"), 128<<10))
	}, nil)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	if _, err := io.WriteString(c, "GET /big HTTP/1.1\r\nHost: t\r\n\r\n"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	_ = c.Close() // 不读响应直接断开

	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get("http://" + addr + "/ok")
	if err != nil {
		t.Fatalf("断连后服务不可用：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("断连后状态码 %d", resp.StatusCode)
	}
}

// 请求体未按 Content-Length 发完就半关闭：应断开且不返回 200。
func TestTruncatedRequestBody(t *testing.T) {
	_, addr := startServer(t, okHandler, nil)

	c := dial(t, addr)
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		t.Skip("不是 TCP 连接")
	}
	if _, err := io.WriteString(c, "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\nabc"); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite 失败：%v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatalf("请求体不完整时不应返回 200")
		}
	}
}

// 头部总量超限（16KiB）应 431，而不是把内存吃满。
func TestHeaderTotalLimit(t *testing.T) {
	_, addr := startServer(t, okHandler, nil)
	c := dial(t, addr)

	var sb strings.Builder
	sb.WriteString("GET /x HTTP/1.1\r\nHost: t\r\n")
	for i := 0; i < 120; i++ { // 120 × ~200B ≈ 24KiB
		fmt.Fprintf(&sb, "X-Pad-%d: %s\r\n", i, strings.Repeat("p", 180))
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(c, sb.String()); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("读响应失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("应 431，got %d", resp.StatusCode)
	}
}

// 处理器 panic 后服务端仍可用（新连接）。
func TestPanicKeepsServerAlive(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) {
		if r.Path() == "/panic" {
			panic("boom")
		}
		_, _ = w.Write([]byte("ok"))
	}, nil)

	resp, err := http.Get("http://" + addr + "/panic")
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != StatusInternalServerError {
		t.Fatalf("应 500，got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + addr + "/ok")
	if err != nil {
		t.Fatalf("panic 后服务不可用：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("panic 后状态码 %d", resp.StatusCode)
	}
}

// 反复建连 / 断开后，连接 goroutine 应被回收。
func TestNoGoroutineLeak(t *testing.T) {
	_, addr := startServer(t, okHandler, func(s *Server) { s.IdleTimeout = 100 * time.Millisecond })

	base := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://" + addr + "/x")
		if err != nil {
			t.Fatalf("第 %d 次请求失败：%v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if runtime.NumGoroutine() <= base+3 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("疑似 goroutine 泄漏：base=%d now=%d", base, runtime.NumGoroutine())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// 100-continue：先回 100，再回最终响应。
func TestExpectContinue(t *testing.T) {
	_, addr := startServer(t, func(w *Response, r *Request) { _, _ = w.Write(r.Body) }, nil)
	c := dial(t, addr)

	raw := "POST /x HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n"
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("写请求失败：%v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读 100 响应失败：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 100 {
		t.Fatalf("应先返回 100，got %d", resp.StatusCode)
	}
	if _, err := io.WriteString(c, "hello"); err != nil {
		t.Fatalf("写请求体失败：%v", err)
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读最终响应失败：%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("最终响应不符：%d %q", resp.StatusCode, body)
	}
}
