// Package minihttp 实现本项目自用的极简 HTTP/1.1 服务端（仅明文，不带 TLS）。
//
// 存在的唯一理由：标准库 net/http 无条件依赖 crypto/tls，而 crypto/tls 又间接
// 带入 crypto/x509 与 crypto/internal/fips140/drbg（约 32MiB BSS）。在 32MB 内存的
// OpenWrt 设备上，这部分开销既占可执行文件体积，也占进程虚拟内存。这里只实现
// 本 API 用得到的子集：请求行 / 头部 / Content-Length 定长请求体 / 明文响应 /
// keep-alive / 超时 / 优雅关闭。
//
// 明确不支持：TLS（HTTPS）、HTTP/2、chunked 请求体、WebSocket、Trailer。
// 需要 HTTPS 时请在前面挂反向代理（或在外部用 stunnel 之类终结 TLS）。
package minihttp

import (
	"bytes"
	"fmt"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTP 状态码（仅列出本实现与调用方用到的部分）。
const (
	StatusOK                          = 200
	StatusNoContent                   = 204
	StatusBadRequest                  = 400
	StatusUnauthorized                = 401
	StatusNotFound                    = 404
	StatusMethodNotAllowed            = 405
	StatusRequestEntityTooLarge       = 413
	StatusURITooLong                  = 414
	StatusRequestHeaderFieldsTooLarge = 431
	StatusInternalServerError         = 500
	StatusNotImplemented              = 501
	StatusServiceUnavailable          = 503
)

func statusText(code int) string {
	switch code {
	case StatusOK:
		return "OK"
	case StatusNoContent:
		return "No Content"
	case StatusBadRequest:
		return "Bad Request"
	case StatusUnauthorized:
		return "Unauthorized"
	case StatusNotFound:
		return "Not Found"
	case StatusMethodNotAllowed:
		return "Method Not Allowed"
	case StatusRequestEntityTooLarge:
		return "Request Entity Too Large"
	case StatusURITooLong:
		return "URI Too Long"
	case StatusRequestHeaderFieldsTooLarge:
		return "Request Header Fields Too Large"
	case StatusInternalServerError:
		return "Internal Server Error"
	case StatusNotImplemented:
		return "Not Implemented"
	case StatusServiceUnavailable:
		return "Service Unavailable"
	default:
		return "Status"
	}
}

// Header 是大小写不敏感的 HTTP 头部容器。
type Header map[string][]string

// Get 返回首个值（不存在时为空串）。
func (h Header) Get(key string) string {
	if vs := h[textproto.CanonicalMIMEHeaderKey(key)]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// Set 覆盖该头的全部值。
func (h Header) Set(key, value string) {
	h[textproto.CanonicalMIMEHeaderKey(key)] = []string{value}
}

// Add 追加一个值。
func (h Header) Add(key, value string) {
	k := textproto.CanonicalMIMEHeaderKey(key)
	h[k] = append(h[k], value)
}

// Values 返回该头的全部值。
func (h Header) Values(key string) []string {
	return h[textproto.CanonicalMIMEHeaderKey(key)]
}

// Request 是一次已解析完成的请求。Body 已按 Content-Length 读入内存（受 MaxBodyBytes 限制）。
type Request struct {
	Method     string
	URL        *url.URL
	Proto      string
	ProtoMajor int
	ProtoMinor int
	Header     Header
	Body       []byte
	Host       string
	RemoteAddr string
}

// Path 返回请求路径（不含 query）。
func (r *Request) Path() string { return r.URL.Path }

// Response 会先在内存中缓冲响应体，待处理器返回后统一写出，
// 从而可以自动补全 Content-Length / Content-Type / Connection。
type Response struct {
	hdr         Header
	status      int
	body        bytes.Buffer
	wroteHeader bool
	close       bool
}

// NewResponse 创建一个 200 的空响应。
func NewResponse() *Response {
	return &Response{hdr: make(Header, 4), status: StatusOK}
}

// Header 返回可写的响应头。
func (w *Response) Header() Header { return w.hdr }

// WriteHeader 记录状态码（重复调用只有首次生效）。
func (w *Response) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
}

// Write 追加响应体（未显式 WriteHeader 时按 200 处理）。
func (w *Response) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}
	return w.body.Write(p)
}

// SetClose 要求服务端在本次响应后关闭连接。
func (w *Response) SetClose() { w.close = true }

// StatusCode 返回当前状态码。
func (w *Response) StatusCode() int { return w.status }

// reset 用于处理器 panic 后重置为错误响应。
func (w *Response) reset(code int, msg string) {
	w.hdr = make(Header, 2)
	w.body.Reset()
	w.status, w.wroteHeader, w.close = code, true, false
	w.hdr.Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.body.WriteString(msg + "\n")
}

// writeTo 把状态行 + 头部 + 响应体写入 bw。head 为真时（HEAD 请求）只写头部。
func (w *Response) writeTo(bw writerStringer, keepAlive, head bool) error {
	code := w.status
	if !w.wroteHeader {
		code = StatusOK
	}
	n := w.body.Len()
	if code == 204 || code == 304 {
		n = 0
	}
	if w.hdr.Get("Content-Type") == "" && n > 0 {
		w.hdr.Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.hdr.Set("Content-Length", strconv.Itoa(n))
	if keepAlive {
		w.hdr.Set("Connection", "keep-alive")
	} else {
		w.hdr.Set("Connection", "close")
	}

	if _, err := fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", code, statusText(code)); err != nil {
		return err
	}
	// RFC 9110 §6.6.1：有钟表的源服务器应为 2xx/3xx/4xx 生成 Date。
	if w.hdr.Get("Date") == "" {
		writeDate(bw, time.Now())
	}
	for k, vs := range w.hdr {
		for _, v := range vs {
			// 防止头部值注入（本项目的头部值均为固定常量，这里只是兜底）。
			if strings.ContainsAny(v, "\r\n") {
				continue
			}
			if _, err := fmt.Fprintf(bw, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	if head || n == 0 {
		return nil
	}
	_, err := bw.Write(w.body.Bytes()[:n])
	return err
}

// writerStringer 是 *bufio.Writer 的最小子集，便于测试替换。
type writerStringer interface {
	Write(p []byte) (int, error)
	WriteString(s string) (int, error)
	WriteByte(c byte) error
}

var (
	weekdayNames = [7]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	monthNames   = [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
)

// writeDate 直接输出 IMF-fixdate 格式的 Date 头。
// 手写而不走 time.Format，是为了避免把格式化 layout 引擎带进二进制（设备上体积敏感）。
func writeDate(bw writerStringer, t time.Time) {
	t = t.UTC()
	_, _ = bw.WriteString("Date: ")
	_, _ = bw.WriteString(weekdayNames[int(t.Weekday())])
	_, _ = bw.WriteString(", ")
	writeNDigits(bw, t.Day(), 2)
	_ = bw.WriteByte(' ')
	_, _ = bw.WriteString(monthNames[int(t.Month())-1])
	_ = bw.WriteByte(' ')
	writeNDigits(bw, t.Year(), 4)
	_ = bw.WriteByte(' ')
	writeNDigits(bw, t.Hour(), 2)
	_ = bw.WriteByte(':')
	writeNDigits(bw, t.Minute(), 2)
	_ = bw.WriteByte(':')
	writeNDigits(bw, t.Second(), 2)
	_, _ = bw.WriteString(" GMT\r\n")
}

func writeNDigits(bw writerStringer, v, n int) {
	var buf [4]byte
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	_, _ = bw.Write(buf[:n])
}
