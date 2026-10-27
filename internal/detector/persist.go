package detector

import (
	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/state"
)

// restore 还原一个告警会话的触发状态（启动时恢复用）。
func (ps *portStat[K]) restore(s state.AlertSession) {
	ps.setIP(s.IP, s.V6)
	ps.alertStartNano = s.AlertStartNano
	ps.lastActiveNano = s.LastActiveNano
	ps.reportedCount = s.ReportedCount
}

// AlertSessions 导出当前处于告警中的端口会话（供 reload 重启继承）。
func (d *Detector) AlertSessions() []state.AlertSession {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []state.AlertSession
	for mac, dev := range d.devices {
		out = appendAlertSessions(out, mac, &dev.v4, false)
		out = appendAlertSessions(out, mac, &dev.v6, true)
	}
	return out
}

// appendAlertSessions 追加某地址族端口表中处于告警中的会话。
func appendAlertSessions[K peerKey](dst []state.AlertSession, mac netutil.MAC, t *portsTable[K], v6 bool) []state.AlertSession {
	for key, ps := range t.m {
		if ps.alertStartNano == 0 {
			continue
		}
		dst = append(dst, state.AlertSession{
			MAC:            mac,
			Port:           key.port,
			Proto:          key.proto,
			V6:             v6,
			IP:             ps.deviceIP(v6),
			AlertStartNano: ps.alertStartNano,
			LastActiveNano: ps.lastActiveNano,
			ReportedCount:  ps.reportedCount,
		})
	}
	return dst
}

// RestoreSessions 还原告警会话（启动时执行）：重建对应端口状态并置回告警起止时间，
// 使后续 Scan 能像重启前一样按流量续期、并在超时后正常触发「PCDN行为结束」回调。
func (d *Detector) RestoreSessions(sessions []state.AlertSession) {
	if len(sessions) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, s := range sessions {
		if !d.filter.Load().AllowKey(s.MAC, s.Port) {
			continue
		}
		dev := d.devices[s.MAC]
		if dev == nil {
			dev = &device{}
			d.devices[s.MAC] = dev
		}
		key := portKey{port: s.Port, proto: s.Proto}
		if s.V6 {
			dev.v6.port(key).restore(s)
			continue
		}
		dev.v4.port(key).restore(s)
	}
}
