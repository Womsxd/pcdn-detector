//go:build !nohttp

package httpapi

import (
	"encoding/json"
	"runtime"
	"strconv"
	"strings"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/minihttp"
	"pcdn-detect/internal/netutil"
)

type healthView struct {
	Status        string `json:"status"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

func (s *Server) handleHealth(w *minihttp.Response, _ *minihttp.Request) {
	writeJSON(w, minihttp.StatusOK, healthView{Status: "ok", UptimeSeconds: s.uptimeSeconds()})
}

type statusView struct {
	Status         string `json:"status"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	TrackedDevices int    `json:"tracked_devices"`
	Alerts         int    `json:"alerts"`
	ActiveBans     int    `json:"active_bans"`
	FullBanned     int    `json:"full_banned"`
	UPnPBlocked    int    `json:"upnp_blocked"`
	UPnPAllowed    int    `json:"upnp_allowed"`
	UPnPAll        bool   `json:"upnp_all"`
}

func (s *Server) handleStatus(w *minihttp.Response, _ *minihttp.Request) {
	v := statusView{Status: "ok", UptimeSeconds: s.uptimeSeconds()}
	if s.det != nil {
		v.TrackedDevices, v.Alerts = s.det.Counts()
	}
	if blk := s.blk.Load(); blk != nil {
		bs := blk.Snapshot()
		v.ActiveBans = len(bs.Bans)
		v.FullBanned = len(bs.FullBanned)
		v.UPnPBlocked = len(bs.UPnPBlocked)
		v.UPnPAllowed = len(bs.UPnPAllowed)
		v.UPnPAll = bs.UPnPAll
	}
	writeJSON(w, minihttp.StatusOK, v)
}

func (s *Server) handleDevices(w *minihttp.Response, _ *minihttp.Request) {
	if s.det == nil {
		writeJSON(w, minihttp.StatusServiceUnavailable, errorBody("检测器未就绪"))
		return
	}
	writeJSON(w, minihttp.StatusOK, s.det.Snapshot())
}

// handlePeers 按需返回单个端口的对端 IP 列表，避免 /devices 汇总时构造大量 IP 字符串。
// 查询参数：mac（必填）、port（必填）、proto（udp/tcp，默认 udp）、v6（默认 false）、limit（默认 device_ip_limit）。
func (s *Server) handlePeers(w *minihttp.Response, r *minihttp.Request) {
	if s.det == nil {
		writeJSON(w, minihttp.StatusServiceUnavailable, errorBody("检测器未就绪"))
		return
	}
	q := r.URL.Query()

	macStr := strings.TrimSpace(q.Get("mac"))
	if macStr == "" {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("缺少 mac 参数"))
		return
	}
	mac, err := netutil.ParseMAC(macStr)
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("mac 参数无效："+err.Error()))
		return
	}

	portStr := strings.TrimSpace(q.Get("port"))
	if portStr == "" {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("缺少 port 参数"))
		return
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("port 参数无效（应为 0-65535）"))
		return
	}

	proto := strings.ToLower(strings.TrimSpace(q.Get("proto")))
	if proto == "" {
		proto = "udp"
	}
	var protoID uint8
	switch proto {
	case "udp":
		protoID = netutil.ProtoUDP
	case "tcp":
		protoID = netutil.ProtoTCP
	default:
		writeJSON(w, minihttp.StatusBadRequest, errorBody("proto 参数无效（可选 udp / tcp）"))
		return
	}

	v6 := false
	if v := strings.TrimSpace(q.Get("v6")); v != "" {
		switch v {
		case "1", "true":
			v6 = true
		case "0", "false":
			v6 = false
		default:
			writeJSON(w, minihttp.StatusBadRequest, errorBody("v6 参数无效（可选 true / false）"))
			return
		}
	}

	limit := s.getIPLimit()
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeJSON(w, minihttp.StatusBadRequest, errorBody("limit 参数无效（应为正整数）"))
			return
		}
		// 不允许超过 device_ip_limit，避免单次响应构造过大内存。
		if n < limit {
			limit = n
		}
	}

	view, ok := s.det.Peers(mac, uint16(port), protoID, v6, limit)
	if !ok {
		writeJSON(w, minihttp.StatusNotFound, errorBody("未找到该设备 / 端口"))
		return
	}
	writeJSON(w, minihttp.StatusOK, view)
}

func (s *Server) handleBlocks(w *minihttp.Response, _ *minihttp.Request) {
	blk := s.blk.Load()
	if blk == nil {
		writeJSON(w, minihttp.StatusOK, blocker.Snapshot{})
		return
	}
	writeJSON(w, minihttp.StatusOK, blk.Snapshot())
}

type unbanRequest struct {
	MAC   string `json:"mac"`
	Port  *int   `json:"port"`
	Proto string `json:"proto"`
}

func (s *Server) handleUnban(w *minihttp.Response, r *minihttp.Request) {
	blk := s.blk.Load()
	if blk == nil {
		writeJSON(w, minihttp.StatusServiceUnavailable, errorBody("防火墙未启用，无法解封"))
		return
	}
	var req unbanRequest
	if err := json.Unmarshal(r.Body, &req); err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("请求体解析失败："+err.Error()))
		return
	}
	if strings.TrimSpace(req.MAC) == "" {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("缺少 mac 字段"))
		return
	}
	if req.Port == nil || *req.Port < 0 || *req.Port > 65535 {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("port 无效（应为 0-65535）"))
		return
	}
	proto := strings.ToLower(strings.TrimSpace(req.Proto))
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("proto 无效（可选 udp / tcp）"))
		return
	}

	n, err := blk.ForceUnban(req.MAC, uint16(*req.Port), proto)
	if err != nil && n == 0 {
		writeJSON(w, minihttp.StatusInternalServerError, errorBody("解封失败："+err.Error()))
		return
	}
	resp := struct {
		Unbanned int    `json:"unbanned"`
		Error    string `json:"error,omitempty"`
	}{Unbanned: n}
	if err != nil {
		resp.Error = err.Error()
	}
	writeJSON(w, minihttp.StatusOK, resp)
}

func (s *Server) handleReload(w *minihttp.Response, _ *minihttp.Request) {
	if s.reload == nil {
		writeJSON(w, minihttp.StatusServiceUnavailable, errorBody("重载不可用"))
		return
	}
	res, err := s.reload()
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody("重载失败："+err.Error()))
		return
	}
	writeJSON(w, minihttp.StatusOK, res)
}

type memStatsView struct {
	Alloc          uint64 `json:"alloc"`
	TotalAlloc     uint64 `json:"total_alloc"`
	Sys            uint64 `json:"sys"`
	HeapAlloc      uint64 `json:"heap_alloc"`
	HeapInuse      uint64 `json:"heap_inuse"`
	HeapObjects    uint64 `json:"heap_objects"`
	HeapSys        uint64 `json:"heap_sys"`
	StackInuse     uint64 `json:"stack_inuse"`
	NumGC          uint32 `json:"num_gc"`
	PauseTotalNs   uint64 `json:"pause_total_ns"`
	LastGCUnixNano uint64 `json:"last_gc_unix_nano"`
}

type memoryView struct {
	GoVersion       string       `json:"go_version"`
	UptimeSeconds   int64        `json:"uptime_seconds"`
	Goroutines      int          `json:"goroutines"`
	GOMAXPROCS      int          `json:"gomaxprocs"`
	NumCPU          int          `json:"num_cpu"`
	GOMEMLIMITBytes int64        `json:"gomemlimit_bytes"`
	GCPercent       int          `json:"gc_percent"`
	MemStats        memStatsView `json:"mem_stats"`
}

func (s *Server) handleMemory(w *minihttp.Response, _ *minihttp.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// gc_percent / gomemlimit 取自 main 记录的当前值：原来的读法要调用
	// debug.SetGCPercent / SetMemoryLimit，二者都会 stop-the-world，且 SetMemoryLimit(-1)
	// 会把堆软上限改成「不限制」（等于静默关闭 memory_limit）。
	writeJSON(w, minihttp.StatusOK, memoryView{
		GoVersion:       runtime.Version(),
		UptimeSeconds:   s.uptimeSeconds(),
		Goroutines:      runtime.NumGoroutine(),
		GOMAXPROCS:      runtime.GOMAXPROCS(0),
		NumCPU:          runtime.NumCPU(),
		GOMEMLIMITBytes: s.memLimit.Load(),
		GCPercent:       int(s.gcPercent.Load()),
		MemStats: memStatsView{
			Alloc:          ms.Alloc,
			TotalAlloc:     ms.TotalAlloc,
			Sys:            ms.Sys,
			HeapAlloc:      ms.HeapAlloc,
			HeapInuse:      ms.HeapInuse,
			HeapObjects:    ms.HeapObjects,
			HeapSys:        ms.HeapSys,
			StackInuse:     ms.StackInuse,
			NumGC:          ms.NumGC,
			PauseTotalNs:   ms.PauseTotalNs,
			LastGCUnixNano: ms.LastGC,
		},
	})
}
