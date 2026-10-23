//go:build !nohttp

// Package httpapi 提供一个默认仅本机的 HTTP API：读取运行时状态、手动解封、重载配置。
//
// 传输层使用项目内置的 internal/minihttp（仅明文 HTTP/1.1），不依赖标准库 net/http，
// 从而不引入 crypto/tls / crypto/x509 及其约 32MiB 的 BSS，显著减小在 32MB 设备上的体积与内存映射。
// 本 API 不提供 HTTPS：需要加密时请在前置反向代理上终结 TLS。
// 默认监听回环地址，可通过 token 启用 Bearer 鉴权。启用与否由调用方（main）依据 [http] 配置决定。
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/logx"
	"pcdn-detect/internal/minihttp"
)

// ReloadResult 描述一次重载的结果。
type ReloadResult struct {
	Applied         []string `json:"applied"`          // 已热应用的配置项
	RestartRequired []string `json:"restart_required"` // 需重启才能生效的配置项
	Restarting      bool     `json:"restarting"`       // 是否已触发重启
}

// ReloadFunc 重载配置文件并返回结果，由 main 注入（封装配置加载 / 覆盖 / 热应用 / 重启编排）。
type ReloadFunc func() (ReloadResult, error)

type handlerFunc func(*minihttp.Response, *minihttp.Request)

// Server 是 HTTP API 服务端。
type Server struct {
	det    *detector.Detector
	blk    atomic.Pointer[blocker.Blocker] // reload 可热更换（启停 / 重建防火墙），故用原子指针
	reload ReloadFunc
	logger *logx.Logger
	listen string

	mu      sync.RWMutex
	token   string
	ipLimit int

	// 当前生效的 GC 目标百分比与堆软上限（字节）：由 main 在启动 / reload 时记录。
	// 二者没有 getter，读取它们的 API 会 stop-the-world 并改写设置，故 /dev/memory
	// 只读这里的值（见 SetRuntimeLimits）。
	gcPercent atomic.Int32
	memLimit  atomic.Int64

	routes map[string]map[string]handlerFunc // path -> method -> handler
}

// processStart 是进程启动时刻：/health 与 /status 的运行时长按进程计（HTTP 监听可能被 reload 原地重启）。
var processStart = time.Now()

// New 构建 HTTP API 服务端。cfg 来自 [http] 配置段；reload 为 nil 时 /reload 返回 503。
// 监听地址与鉴权方式由 config.HTTPConfig.Validate 校验（与 --test-config / reload 预检共用）：
// 非回环地址必须配置 token，避免无意暴露。
func New(det *detector.Detector, blk *blocker.Blocker, cfg config.HTTPConfig, reload ReloadFunc, logger *logx.Logger) (*Server, error) {
	listen := cfg.ListenAddr()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	token := cfg.BearerToken()
	if token == "" && logger != nil {
		if host, _, err := net.SplitHostPort(listen); err == nil && !config.IsLoopbackHost(host) {
			logger.Warnf("警告：HTTP API 绑定在非回环地址 %s 且未启用鉴权（token = %q），请确保所在网络可信", listen, config.TokenAllowNoToken)
		}
	}

	s := &Server{
		det:     det,
		reload:  reload,
		logger:  logger,
		listen:  listen,
		token:   token,
		ipLimit: cfg.DeviceIPLimitValue(),
	}
	// 默认值：Go 的默认 GOGC 与「不限制堆」；main 会在启动后立即以实际生效值覆盖。
	s.gcPercent.Store(100)
	s.memLimit.Store(math.MaxInt64)
	s.blk.Store(blk)
	s.routes = s.buildRoutes()
	return s, nil
}

// SetRuntimeLimits 记录当前生效的 GC 目标百分比与堆软上限（字节），供 /dev/memory 读取。
// 这两个运行时参数没有 getter；读取它们的 API（debug.SetGCPercent / debug.SetMemoryLimit）
// 会 stop-the-world 并改写设置（SetMemoryLimit(-1) 会关闭堆软上限），因此必须由 main
// 在启动与 reload 时记录，查询接口只读字段，不再触碰运行时。
func (s *Server) SetRuntimeLimits(gcPercent int, memLimitBytes int64) {
	s.gcPercent.Store(int32(gcPercent))
	s.memLimit.Store(memLimitBytes)
}

// SetBlocker 热更换封禁协调器（供 reload 启停 / 重建防火墙时通知 HTTP 层）。
// 传 nil 表示防火墙已关闭；各 handler 在入口只 Load 一次，避免判空后指针变化。
func (s *Server) SetBlocker(blk *blocker.Blocker) {
	s.blk.Store(blk)
}

// Handler 返回包装了鉴权中间件的处理器。
func (s *Server) Handler() minihttp.Handler {
	return s.auth(s.dispatch)
}

// transport 构建带本项目策略（超时上限、统一 JSON 错误体）的传输层。
func (s *Server) transport() *minihttp.Server {
	return &minihttp.Server{
		Addr:     s.listen,
		Handler:  s.Handler(),
		ErrorLog: s.logger.Std(),
		// 协议级错误（400/413/414/431/501）也用统一的 JSON 错误体。
		ErrorHandler: func(w *minihttp.Response, code int, msg string) {
			writeJSON(w, code, errorBody(msg))
		},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxBodyBytes:      1 << 20,
	}
}

// Run 启动服务并在 ctx 取消后优雅关闭。
func (s *Server) Run(ctx context.Context) error {
	srv := s.transport()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, minihttp.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// SetToken 热更新 Bearer 令牌（供 reload 热应用）。
func (s *Server) SetToken(token string) {
	s.mu.Lock()
	s.token = token
	s.mu.Unlock()
}

// SetDeviceIPLimit 热更新 /devices 的对端 IP 上限（供 reload 热应用）。
func (s *Server) SetDeviceIPLimit(n int) {
	if n <= 0 {
		n = 1
	}
	s.mu.Lock()
	s.ipLimit = n
	s.mu.Unlock()
}

func (s *Server) buildRoutes() map[string]map[string]handlerFunc {
	r := make(map[string]map[string]handlerFunc, 8)
	add := func(method, path string, h handlerFunc) {
		if r[path] == nil {
			r[path] = make(map[string]handlerFunc, 2)
		}
		r[path][method] = h
	}
	add("GET", "/api/v1/health", s.handleHealth)
	add("GET", "/api/v1/status", s.handleStatus)
	add("GET", "/api/v1/devices", s.handleDevices)
	add("GET", "/api/v1/peers", s.handlePeers)
	add("GET", "/api/v1/blocks", s.handleBlocks)
	add("POST", "/api/v1/unban", s.handleUnban)
	add("POST", "/api/v1/reload", s.handleReload)
	add("GET", "/dev/memory", s.handleMemory)
	return r
}

// dispatch 按「精确路径 + 方法」路由；方法不匹配返回 405 并带 Allow 头。
func (s *Server) dispatch(w *minihttp.Response, r *minihttp.Request) {
	methods, ok := s.routes[r.Path()]
	if !ok {
		writeJSON(w, minihttp.StatusNotFound, errorBody("未找到该端点"))
		return
	}
	if h, ok := methods[r.Method]; ok {
		h(w, r)
		return
	}
	// 与 net/http 语义一致：GET 注册同时接受 HEAD（响应体由传输层丢弃）。
	if r.Method == "HEAD" {
		if h, ok := methods["GET"]; ok {
			h(w, r)
			return
		}
	}
	allow := make([]string, 0, len(methods))
	for m := range methods {
		allow = append(allow, m)
	}
	sort.Strings(allow)
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeJSON(w, minihttp.StatusMethodNotAllowed, errorBody("方法不允许"))
}

func (s *Server) auth(next minihttp.Handler) minihttp.Handler {
	return func(w *minihttp.Response, r *minihttp.Request) {
		s.mu.RLock()
		token := s.token
		s.mu.RUnlock()
		if token != "" {
			const prefix = "Bearer "
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, prefix) ||
				subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, prefix)), []byte(token)) != 1 {
				writeJSON(w, minihttp.StatusUnauthorized, errorBody("未授权：需要有效的 Bearer 令牌"))
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) uptimeSeconds() int64 {
	return int64(time.Since(processStart).Seconds())
}

func (s *Server) getIPLimit() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ipLimit
}

func writeJSON(w *minihttp.Response, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
