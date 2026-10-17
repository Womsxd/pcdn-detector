//go:build !nohttp

package httpapi

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"strings"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/minihttp"
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
	if s.blk != nil {
		bs := s.blk.Snapshot()
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
	writeJSON(w, minihttp.StatusOK, s.det.Snapshot(s.getIPLimit()))
}

func (s *Server) handleBlocks(w *minihttp.Response, _ *minihttp.Request) {
	if s.blk == nil {
		writeJSON(w, minihttp.StatusOK, blocker.Snapshot{})
		return
	}
	writeJSON(w, minihttp.StatusOK, s.blk.Snapshot())
}

type unbanRequest struct {
	MAC   string `json:"mac"`
	Port  *int   `json:"port"`
	Proto string `json:"proto"`
}

func (s *Server) handleUnban(w *minihttp.Response, r *minihttp.Request) {
	if s.blk == nil {
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

	n, err := s.blk.ForceUnban(req.MAC, uint16(*req.Port), proto)
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

	// 读取当前 gc_percent：SetGCPercent(-1) 返回先前值，随即写回以免改变运行状态。
	prev := debug.SetGCPercent(-1)
	debug.SetGCPercent(prev)

	writeJSON(w, minihttp.StatusOK, memoryView{
		GoVersion:       runtime.Version(),
		UptimeSeconds:   s.uptimeSeconds(),
		Goroutines:      runtime.NumGoroutine(),
		GOMAXPROCS:      runtime.GOMAXPROCS(0),
		NumCPU:          runtime.NumCPU(),
		GOMEMLIMITBytes: debug.SetMemoryLimit(-1),
		GCPercent:       prev,
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
