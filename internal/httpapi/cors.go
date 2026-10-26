package httpapi

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"pcdn-detect/internal/minihttp"
)

// corsPolicy 是 CORS 配置的运行时快照（配置热重载时整体替换）。
type corsPolicy struct {
	origins     []string // 规范化后的允许来源；与 anyOrigin 同时为空表示不启用 CORS
	anyOrigin   bool     // 允许任意来源（配置了 "*"）
	credentials bool     // 是否回写 Access-Control-Allow-Credentials
	maxAge      int      // 预检结果缓存秒数；<=0 表示不返回 Access-Control-Max-Age
}

// newCORSPolicy 规范化来源列表：去空白、统一 scheme/host 大小写、去掉末尾 "/"、去重。
func newCORSPolicy(origins []string, allowCredentials bool, maxAgeSeconds int) corsPolicy {
	p := corsPolicy{credentials: allowCredentials, maxAge: maxAgeSeconds}
	if p.maxAge < 0 {
		p.maxAge = 0
	}
	for _, o := range origins {
		o = canonicalOrigin(o)
		if o == "" {
			continue
		}
		if o == "*" {
			p.anyOrigin = true
			continue
		}
		if !containsString(p.origins, o) {
			p.origins = append(p.origins, o)
		}
	}
	// 通配来源与凭据互斥（Validate 已拒绝该组合）：兜底关掉凭据，
	// 避免把任意来源的携带凭据请求放行。
	if p.anyOrigin {
		p.credentials = false
	}
	return p
}

// enabled 表示是否启用了 CORS。
func (p corsPolicy) enabled() bool { return p.anyOrigin || len(p.origins) > 0 }

// allowOrigin 返回应回写的 Access-Control-Allow-Origin；空串表示该来源不被允许。
func (p corsPolicy) allowOrigin(origin string) string {
	if p.anyOrigin {
		return "*"
	}
	if containsString(p.origins, canonicalOrigin(origin)) {
		return origin
	}
	return ""
}

// canonicalOrigin 把来源规范化为 scheme://host[:port]（小写、无末尾 "/"）。
// 非法输入按小写原文返回，交由配置校验兜底。
func canonicalOrigin(origin string) string {
	o := strings.TrimSpace(origin)
	if o == "*" {
		return "*"
	}
	o = strings.TrimSuffix(o, "/")
	if u, err := url.Parse(o); err == nil && u.Host != "" && u.Path == "" {
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	}
	return strings.ToLower(o)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// SetCORS 更新 CORS 策略：New 在启动时调用，reload 用于热应用。
// 传入空来源表示关闭 CORS；maxAgeSeconds <= 0 表示不返回 Access-Control-Max-Age。
func (s *Server) SetCORS(origins []string, allowCredentials bool, maxAgeSeconds int) {
	p := newCORSPolicy(origins, allowCredentials, maxAgeSeconds)
	s.mu.Lock()
	s.cors = p
	s.mu.Unlock()
}

// corsSnapshot 返回当前策略（快照内的切片发布后不再修改，可安全在锁外使用）。
func (s *Server) corsSnapshot() corsPolicy {
	s.mu.RLock()
	p := s.cors
	s.mu.RUnlock()
	return p
}

// withCORS 是最外层中间件：为带 Origin 的请求回写 CORS 响应头，并在预检（OPTIONS）时直接短路。
// 必须包在 auth 之外：预检由浏览器自动发出、不携带 Authorization，进入鉴权会被 401 拦掉；
// 且路由表未注册 OPTIONS（直接进入 dispatch 会得到 405）。
func (s *Server) withCORS(next minihttp.Handler) minihttp.Handler {
	return func(w *minihttp.Response, r *minihttp.Request) {
		p := s.corsSnapshot()
		origin := r.Header.Get("Origin")
		if !p.enabled() || origin == "" {
			next(w, r)
			return
		}

		h := w.Header()
		h.Add("Vary", "Origin")
		allow := p.allowOrigin(origin)
		if allow != "" {
			h.Set("Access-Control-Allow-Origin", allow)
			if p.credentials {
				h.Set("Access-Control-Allow-Credentials", "true")
			}
		}

		if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
			// 来源未被允许：仍按预检语义返回 204，但不暴露路由信息。
			if allow == "" {
				w.WriteHeader(minihttp.StatusNoContent)
				return
			}
			s.preflight(w, r, p)
			return
		}
		next(w, r)
	}
}

// preflight 响应 CORS 预检：允许的方法按实际路由表计算，未知路径 / 未注册方法
// 沿用 dispatch 的 404 / 405 语义（浏览器侧同样会因缺少允许头而拒绝该请求）。
func (s *Server) preflight(w *minihttp.Response, r *minihttp.Request, p corsPolicy) {
	h := w.Header()
	h.Add("Vary", "Access-Control-Request-Method")
	if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
		// 回写浏览器请求的头名：来源已按白名单校验，不会把任意头用于他人来源。
		h.Set("Access-Control-Allow-Headers", reqHeaders)
		h.Add("Vary", "Access-Control-Request-Headers")
	} else {
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	}

	methods, ok := s.routes[r.Path()]
	if !ok {
		writeJSON(w, minihttp.StatusNotFound, errorBody("未找到该端点"))
		return
	}
	allow := corsAllowMethods(methods)
	h.Set("Access-Control-Allow-Methods", strings.Join(allow, ", "))

	reqMethod := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
	if !corsMethodAllowed(methods, reqMethod) {
		h.Set("Allow", strings.Join(allow, ", "))
		writeJSON(w, minihttp.StatusMethodNotAllowed, errorBody("方法不允许"))
		return
	}
	if p.maxAge > 0 {
		h.Set("Access-Control-Max-Age", strconv.Itoa(p.maxAge))
	}
	w.WriteHeader(minihttp.StatusNoContent)
}

// corsAllowMethods 返回某路径允许的方法（排序；GET 存在时补上 HEAD，与 dispatch 语义一致）。
func corsAllowMethods(methods map[string]handlerFunc) []string {
	out := make([]string, 0, len(methods)+1)
	for m := range methods {
		out = append(out, m)
	}
	if _, hasGet := methods["GET"]; hasGet {
		if _, hasHead := methods["HEAD"]; !hasHead {
			out = append(out, "HEAD")
		}
	}
	sort.Strings(out)
	return out
}

// corsMethodAllowed 判断预检请求的方法是否被该路径接受。
func corsMethodAllowed(methods map[string]handlerFunc, method string) bool {
	if _, ok := methods[method]; ok {
		return true
	}
	if method == "HEAD" {
		_, ok := methods["GET"]
		return ok
	}
	return false
}
