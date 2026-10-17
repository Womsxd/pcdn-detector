package minihttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerClosed 在监听被 Shutdown / Close 关闭后由 Serve 返回（与 net/http 语义一致）。
var ErrServerClosed = errors.New("minihttp: 服务已关闭")

// Handler 处理一次请求。
type Handler func(w *Response, r *Request)

// Server 是一个仅支持明文 HTTP/1.1 的最小服务端。
//
// 零值不可直接使用：必须设置 Handler；其余字段留空时使用默认值
// （读头 5s、空闲 30s、写 10s、头部 16KiB、请求体 1MiB）。
type Server struct {
	Addr     string
	Handler  Handler
	ErrorLog *log.Logger

	// ErrorHandler 可选：自定义协议级错误（400/413/414/431/501）的响应体，
	// 供调用方统一成 JSON 等格式。为 nil 时退回 text/plain。
	ErrorHandler func(w *Response, code int, msg string)

	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	MaxBodyBytes      int64

	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	serving  bool
	closed   bool
	shutdown atomic.Bool
}

func (s *Server) readHeaderTimeout() time.Duration {
	if s.ReadHeaderTimeout > 0 {
		return s.ReadHeaderTimeout
	}
	return 5 * time.Second
}

func (s *Server) writeTimeout() time.Duration {
	if s.WriteTimeout > 0 {
		return s.WriteTimeout
	}
	return 10 * time.Second
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return 30 * time.Second
}

func (s *Server) maxHeaderBytes() int {
	if s.MaxHeaderBytes > 0 {
		return s.MaxHeaderBytes
	}
	return 16 << 10
}

func (s *Server) maxBodyBytes() int64 {
	if s.MaxBodyBytes > 0 {
		return s.MaxBodyBytes
	}
	return 1 << 20
}

// ListenAndServe 监听 s.Addr 并开始服务。
func (s *Server) ListenAndServe() error {
	if s.Handler == nil {
		return errors.New("minihttp: Handler 为 nil")
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve 在已有监听器上服务，直到监听被关闭（返回 ErrServerClosed）。
func (s *Server) Serve(ln net.Listener) error {
	if s.Handler == nil {
		return errors.New("minihttp: Handler 为 nil")
	}
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return errors.New("minihttp: 重复 Serve")
	}
	s.serving, s.ln = true, ln
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.mu.Unlock()

	var delay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.shutdown.Load() || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			// 临时性错误（如 EMFILE / EAGAIN）退避重试，避免服务直接退出。
			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = nc.Close()
			continue
		}
		s.conns[nc] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveConn(nc)
	}
}

// Shutdown 停止接收新连接，并等待在途请求完成；超时（ctx 结束）则强制断开。
// 已有连接上的响应不受影响：这里只是中断「等待下一个请求」的读取。
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdown.Store(true)
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now())
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// 与 net/http 一致：超时后强制断开连接并立即返回，不等待卡住的处理器。
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		return ctx.Err()
	}
}

// Close 立即关闭监听与所有连接。
func (s *Server) Close() error {
	s.shutdown.Store(true)
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) serveConn(nc net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, nc)
		s.mu.Unlock()
		_ = nc.Close()
		s.wg.Done()
	}()

	br := bufio.NewReaderSize(nc, 4096)
	bw := bufio.NewWriterSize(nc, 4096)
	remote := nc.RemoteAddr().String()
	timeout := s.readHeaderTimeout()

	for {
		if s.shutdown.Load() {
			return
		}
		_ = nc.SetReadDeadline(time.Now().Add(timeout))

		req, err := s.readRequest(br, bw, remote)
		if err != nil {
			var pe *protoError
			if errors.As(err, &pe) {
				_ = nc.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
				s.writeError(bw, pe)
				_ = bw.Flush()
			}
			return
		}
		// 第二个请求起按空闲超时等待。
		timeout = s.idleTimeout()

		resp := NewResponse()
		s.callHandler(resp, req)
		keepAlive := s.keepAlive(req, resp)

		_ = nc.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
		if err := resp.writeTo(bw, keepAlive, req.Method == "HEAD"); err != nil {
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}
		if !keepAlive || s.shutdown.Load() {
			return
		}
	}
}

func (s *Server) callHandler(resp *Response, req *Request) {
	defer func() {
		if v := recover(); v != nil {
			if s.ErrorLog != nil {
				s.ErrorLog.Printf("HTTP 处理器 panic：%v\n%s", v, debug.Stack())
			}
			resp.reset(StatusInternalServerError, "Internal Server Error")
		}
	}()
	s.Handler(resp, req)
}

func (s *Server) keepAlive(req *Request, resp *Response) bool {
	if resp.close || req.ProtoMajor != 1 {
		return false
	}
	conn := req.Header.Get("Connection")
	if req.ProtoMinor == 0 { // HTTP/1.0 默认短连接
		return strings.EqualFold(conn, "keep-alive")
	}
	return !strings.EqualFold(conn, "close")
}

// protoError 是可直接映射为 HTTP 状态码的协议错误。
type protoError struct {
	code int
	msg  string
}

func (e *protoError) Error() string { return e.msg }

func badRequest(msg string) error { return &protoError{StatusBadRequest, msg} }

func (s *Server) readRequest(br *bufio.Reader, bw *bufio.Writer, remote string) (*Request, error) {
	// 请求行前允许少量空行（RFC 7230 建议忽略）。
	line, err := readLine(br)
	if err != nil {
		// 请求行过长按 414 处理（头部行过长为 431），与 net/http 一致。
		if errors.Is(err, errLineTooLong) {
			return nil, &protoError{StatusURITooLong, "请求行过长"}
		}
		return nil, err
	}
	// 与 net/http 一致：请求行不能是空行（不接受前导 CRLF）。
	if line == "" {
		return nil, badRequest("请求行缺失")
	}

	method, target, proto, ok := parseRequestLine(line)
	if !ok {
		return nil, badRequest("请求行格式错误")
	}

	hdr := make(Header, 8)
	limit := s.maxHeaderBytes()
	total := len(line)
	for {
		l, err := readLine(br)
		if err != nil {
			return nil, err
		}
		if l == "" {
			break
		}
		total += len(l)
		if total > limit {
			return nil, &protoError{StatusRequestHeaderFieldsTooLarge, "请求头过大"}
		}
		name, value, found := strings.Cut(l, ":")
		if !found {
			return nil, badRequest("请求头格式错误")
		}
		name = strings.TrimSpace(name)
		if !validHeaderName(name) {
			return nil, badRequest("请求头名无效")
		}
		value = strings.TrimSpace(value)
		if !validHeaderValue(value) {
			return nil, badRequest("请求头值包含非法字符")
		}
		hdr.Add(name, value)
	}

	// 只支持 Content-Length 定长请求体（本 API 的请求体均为小 JSON）；
	// 分块等其它传输编码明确不支持，返回 501（net/http 会解析 chunked，这里是有意差异）。
	if te := hdr.Get("Transfer-Encoding"); te != "" && !strings.EqualFold(te, "identity") {
		return nil, &protoError{StatusNotImplemented, "不支持分块请求体，请使用 Content-Length"}
	}

	var body []byte
	n, hasCL, err := parseContentLength(hdr)
	if err != nil {
		return nil, err
	}
	if hasCL {
		if n > s.maxBodyBytes() {
			return nil, &protoError{StatusRequestEntityTooLarge, "请求体过大"}
		}
		if strings.EqualFold(hdr.Get("Expect"), "100-continue") {
			if _, err := bw.WriteString("HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return nil, err
			}
			if err := bw.Flush(); err != nil {
				return nil, err
			}
		}
		if n > 0 {
			body = make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				return nil, err
			}
		}
	}

	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, badRequest("请求路径无效")
	}
	major, minor, ok := parseProto(proto)
	if !ok {
		return nil, badRequest("HTTP 版本不支持")
	}
	host := hdr.Get("Host")
	if host == "" {
		host = u.Host
	}
	// 与 net/http 一致：HTTP/1.1 必须有 Host（绝对形式 URI 可提供）。
	if major == 1 && minor >= 1 && host == "" {
		return nil, badRequest("HTTP/1.1 请求缺少 Host 头")
	}
	return &Request{
		Method:     method,
		URL:        u,
		Proto:      proto,
		ProtoMajor: major,
		ProtoMinor: minor,
		Header:     hdr,
		Body:       body,
		Host:       host,
		RemoteAddr: remote,
	}, nil
}

var errLineTooLong = &protoError{StatusRequestHeaderFieldsTooLarge, "请求行或请求头过长"}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	return string(line), nil
}

func parseRequestLine(line string) (method, target, proto string, ok bool) {
	first := strings.IndexByte(line, ' ')
	last := strings.LastIndexByte(line, ' ')
	if first <= 0 || last <= first {
		return "", "", "", false
	}
	method, target, proto = line[:first], line[first+1:last], line[last+1:]
	if target == "" || !strings.HasPrefix(proto, "HTTP/1.") || !isToken(method) {
		return "", "", "", false
	}
	return method, target, proto, true
}

// parseContentLength 按 net/http 的规则解析 Content-Length：
// 只接受纯 ASCII 数字；重复出现时必须完全一致，否则视为请求走私风险直接拒绝。
func parseContentLength(hdr Header) (n int64, present bool, err error) {
	vals := hdr.Values("Content-Length")
	if len(vals) == 0 {
		return 0, false, nil
	}
	first := strings.TrimSpace(vals[0])
	if !isDigits(first) {
		return 0, true, badRequest("Content-Length 无效")
	}
	for _, v := range vals[1:] {
		if strings.TrimSpace(v) != first {
			return 0, true, badRequest("Content-Length 重复且冲突")
		}
	}
	n, perr := strconv.ParseInt(first, 10, 64)
	if perr != nil {
		return 0, true, badRequest("Content-Length 超出范围")
	}
	return n, true, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isToken 判断是否为 RFC 7230 的 token（用于方法名 / 头部名）。
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
			c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
			c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

func validHeaderName(s string) bool { return isToken(s) }

// validHeaderValue 拒绝控制字符（允许水平制表符），避免头部注入。
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || (c >= 0x20 && c != 0x7f) {
			continue
		}
		return false
	}
	return true
}

func parseProto(proto string) (major, minor int, ok bool) {
	rest := strings.TrimPrefix(proto, "HTTP/")
	maj, min, found := strings.Cut(rest, ".")
	if !found {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(maj)
	minor, err2 := strconv.Atoi(min)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// writeError 输出协议级错误响应并关闭连接。
func (s *Server) writeError(bw *bufio.Writer, pe *protoError) {
	resp := NewResponse()
	resp.WriteHeader(pe.code)
	if s.ErrorHandler != nil {
		s.ErrorHandler(resp, pe.code, pe.msg)
	} else {
		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = resp.Write([]byte(pe.msg + "\n"))
	}
	_ = resp.writeTo(bw, false, false)
}
