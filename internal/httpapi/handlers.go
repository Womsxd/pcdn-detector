package httpapi

import (
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"strings"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/detector"
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
		// /status 只需要计数：不要为此构造完整封禁快照（复制条目 + 多次排序）。
		c := blk.Counts()
		v.ActiveBans = c.ActiveBans
		v.FullBanned = c.FullBanned
		v.UPnPBlocked = c.UPnPBlocked
		v.UPnPAllowed = c.UPnPAllowed
		v.UPnPAll = c.UPnPAll
	}
	writeJSON(w, minihttp.StatusOK, v)
}

// viewProto 是某设备在「地址族 + 传输层协议」下的端口统计。
// Ports 为当前跟踪的端口条目数，Banned 为其中处于封禁状态的条目数。
type viewProto struct {
	Ports  int `json:"ports"`
	Banned int `json:"banned"`
}

// viewFamily 是某设备在一个地址族下的端口统计：
// Ports / Banned 为该地址族合计，UDP / TCP 为按传输层协议的拆分。
type viewFamily struct {
	Ports  int       `json:"ports"`
	Banned int       `json:"banned"`
	UDP    viewProto `json:"udp"`
	TCP    viewProto `json:"tcp"`
}

// add 把一个端口条目计入地址族合计与对应协议的统计。
func (f *viewFamily) add(proto string, banned bool) {
	f.Ports++
	if banned {
		f.Banned++
	}
	p := &f.UDP
	if proto == "tcp" {
		p = &f.TCP
	}
	p.Ports++
	if banned {
		p.Banned++
	}
}

type deviceSummaryView struct {
	MAC  string     `json:"mac"`
	IPv4 viewFamily `json:"ipv4"`
	IPv6 viewFamily `json:"ipv6"`
}

type devicesView struct {
	TrackedDevices int                 `json:"tracked_devices"`
	Alerts         int                 `json:"alerts"`
	PortEvictions  int64               `json:"port_evictions"`
	PortDrops      int64               `json:"port_drops"`
	Devices        []deviceSummaryView `json:"devices"`
}

// devicePortView 在 detector.PortView 上补充当前封禁状态。
type devicePortView struct {
	detector.PortView
	Banned bool `json:"banned"`
}

type deviceDetailView struct {
	MAC        string           `json:"mac"`
	FullBanned bool             `json:"full_banned"`
	IPv4       viewFamily       `json:"ipv4"`
	IPv6       viewFamily       `json:"ipv6"`
	Page       int64            `json:"page"`      // 当前页码（从 1 开始）
	Limit      int              `json:"limit"`     // 每页条目数（已按硬上限收敛）
	Matched    int              `json:"matched"`   // 符合筛选条件的端口条目总数（不受分页影响）
	Truncated  bool             `json:"truncated"` // 本页之后是否还有匹配条目
	Ports      []devicePortView `json:"ports"`
}

// peersView 在 detector.PeerView 上补充分页信息。
type peersView struct {
	detector.PeerView
	Page  int64 `json:"page"`
	Limit int   `json:"limit"`
}

// handleDevices 返回设备级汇总：每设备 IPv4 / IPv6 当前跟踪的端口条目数与封禁条目数。
// 端口明细改由 /api/v1/device?mac=... 按需查询，避免一次响应携带全部端口。
func (s *Server) handleDevices(w *minihttp.Response, _ *minihttp.Request) {
	if s.det == nil {
		writeJSON(w, minihttp.StatusServiceUnavailable, errorBody("检测器未就绪"))
		return
	}
	ov := s.det.Overview()
	ix := s.banIndex()
	out := devicesView{
		TrackedDevices: ov.TrackedDevices,
		Alerts:         ov.Alerts,
		PortEvictions:  ov.PortEvictions,
		PortDrops:      ov.PortDrops,
		Devices:        make([]deviceSummaryView, 0, len(ov.Devices)),
	}
	for _, dp := range ov.Devices {
		dv := deviceSummaryView{MAC: dp.MAC}
		for _, k := range dp.Keys {
			stat := &dv.IPv4
			if k.V6 {
				stat = &dv.IPv6
			}
			proto := protoLabel(k.Proto)
			stat.add(proto, ix.Banned(dp.MAC, k.Port, proto, k.V6))
		}
		out.Devices = append(out.Devices, dv)
	}
	writeJSON(w, minihttp.StatusOK, out)
}

// handleDevice 返回单设备的端口明细，支持按地址族与封禁状态筛选。
// 查询参数：mac（必填）、family=all|v4|v6（默认 all）、state=all|banned|unbanned（默认 all）、
// limit（默认 200，最多 1000）、page（默认 1，从 1 开始）。
// 响应中的 ipv4 / ipv6 统计始终为该设备的全量口径，不受 family / state / limit / page 影响。
func (s *Server) handleDevice(w *minihttp.Response, r *minihttp.Request) {
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

	v6, err := parseFamilyParam(q.Get("family"))
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody(err.Error()))
		return
	}
	state, err := parseStateParam(q.Get("state"))
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody(err.Error()))
		return
	}

	limit := defaultDevicePortLimit
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeJSON(w, minihttp.StatusBadRequest, errorBody("limit 参数无效（应为正整数）"))
			return
		}
		// 与 /peers 一致：超过硬上限时收敛到上限，避免单次响应构造过大内存。
		limit = n
		if limit > maxDevicePortLimit {
			limit = maxDevicePortLimit
		}
	}
	page, err := parsePageParam(q.Get("page"))
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody(err.Error()))
		return
	}
	offset := pageOffset(page, limit)

	dv, ok := s.det.DeviceSnapshot(mac)
	if !ok {
		writeJSON(w, minihttp.StatusNotFound, errorBody("未找到该设备"))
		return
	}
	ix := s.banIndex()
	out := deviceDetailView{
		MAC:        dv.MAC,
		FullBanned: ix.FullBanned(dv.MAC),
		Page:       page,
		Limit:      limit,
		Ports:      make([]devicePortView, 0, min(limit, len(dv.Ports))),
	}
	for _, p := range dv.Ports {
		banned := ix.Banned(dv.MAC, p.Port, p.Proto, p.V6)
		stat := &out.IPv4
		if p.V6 {
			stat = &out.IPv6
		}
		stat.add(p.Proto, banned)
		if v6 != nil && p.V6 != *v6 {
			continue
		}
		if (state == stateBanned && !banned) || (state == stateUnbanned && banned) {
			continue
		}
		idx := int64(out.Matched)
		out.Matched++
		if idx < offset {
			continue
		}
		if len(out.Ports) < limit {
			out.Ports = append(out.Ports, devicePortView{PortView: p, Banned: banned})
		}
	}
	out.Truncated = int64(out.Matched) > offset+int64(len(out.Ports))
	writeJSON(w, minihttp.StatusOK, out)
}

const (
	defaultDevicePortLimit = 200  // /device 默认返回的端口条目数
	maxDevicePortLimit     = 1000 // /device 单次返回的端口条目硬上限
)

type portStateFilter uint8

const (
	stateAll portStateFilter = iota
	stateBanned
	stateUnbanned
)

// parseFamilyParam 解析 family 查询参数：all（默认）返回 nil，v4 返回 false，v6 返回 true。
// 兼容 ipv4 / ipv6 / 4 / 6 写法。
func parseFamilyParam(v string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "all":
		return nil, nil
	case "v4", "ipv4", "4":
		f := false
		return &f, nil
	case "v6", "ipv6", "6":
		t := true
		return &t, nil
	}
	return nil, errors.New("family 参数无效（可选 all / v4 / v6）")
}

// parsePageParam 解析 page 查询参数（1-based，默认 1）。
func parsePageParam(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 1, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("page 参数无效（应为正整数）")
	}
	return n, nil
}

// pageOffset 把 1-based 页码换算为偏移。页码极大时返回一个必然越界的偏移，避免整数溢出。
func pageOffset(page int64, limit int) int64 {
	const maxOffset = int64(1) << 62
	if limit < 1 {
		limit = 1
	}
	if page-1 > maxOffset/int64(limit) {
		return maxOffset
	}
	return (page - 1) * int64(limit)
}

// parseStateParam 解析 state 查询参数：all（默认）/ banned / unbanned。
func parseStateParam(v string) (portStateFilter, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "all":
		return stateAll, nil
	case "banned":
		return stateBanned, nil
	case "unbanned":
		return stateUnbanned, nil
	}
	return stateAll, errors.New("state 参数无效（可选 all / banned / unbanned）")
}

// protoLabel 返回传输层协议的展示名，与 detector 内部命名保持一致。
func protoLabel(proto uint8) string {
	if proto == netutil.ProtoTCP {
		return "tcp"
	}
	return "udp"
}

// banIndex 返回当前封禁状态的只读索引；防火墙未启用时为零值（不含任何规则）。
func (s *Server) banIndex() blocker.BanIndex {
	if blk := s.blk.Load(); blk != nil {
		return blk.BanIndex()
	}
	return blocker.BanIndex{}
}

// handlePeers 按需返回单个端口的对端 IP 列表，避免 /devices 与 /device 构造大量 IP 字符串。
// 查询参数：mac（必填）、port（必填）、proto（udp/tcp，默认 udp）、v6（默认 false）、
// limit（默认 device_ip_limit，不能超过该值）、page（默认 1，从 1 开始）。
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
	page, err := parsePageParam(q.Get("page"))
	if err != nil {
		writeJSON(w, minihttp.StatusBadRequest, errorBody(err.Error()))
		return
	}
	offset := pageOffset(page, limit)

	view, ok := s.det.PeersPage(mac, uint16(port), protoID, v6, offset, limit)
	if !ok {
		writeJSON(w, minihttp.StatusNotFound, errorBody("未找到该设备 / 端口"))
		return
	}
	writeJSON(w, minihttp.StatusOK, peersView{PeerView: view, Page: page, Limit: limit})
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
