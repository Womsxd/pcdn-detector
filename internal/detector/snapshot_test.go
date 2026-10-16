package detector

import (
	"strings"
	"testing"
	"time"

	"pcdn-detect/internal/filter"
)

// Snapshot 应反映端口统计与对端上限，AlertSessions/RestoreSessions 应可往返。
func TestSnapshotAndSessions(t *testing.T) {
	d, _ := newTestDetector(2, time.Minute, 10*time.Minute)
	now := time.Now()
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}, now)
	d.Scan(now) // 触发告警

	snap := d.Snapshot(2)
	if snap.TrackedDevices != 1 || snap.Alerts != 1 {
		t.Fatalf("快照计数不符：%+v", snap)
	}
	if len(snap.Devices) != 1 || len(snap.Devices[0].Ports) != 1 {
		t.Fatalf("设备/端口数不符：%+v", snap.Devices)
	}
	p := snap.Devices[0].Ports[0]
	if !p.Alerting || p.PeerCount != 3 || !p.Truncated || len(p.PeerIPs) != 2 {
		t.Fatalf("端口快照不符：%+v", p)
	}

	sessions := d.AlertSessions()
	if len(sessions) != 1 {
		t.Fatalf("应有 1 个告警会话，got %d", len(sessions))
	}
	if sessions[0].Port != 40000 || sessions[0].Proto == 0 || sessions[0].AlertStartNano == 0 {
		t.Fatalf("会话内容不符：%+v", sessions[0])
	}

	// 还原到新检测器：告警会话应能续存，并在超时后正常结束。
	d2, _ := newTestDetector(2, time.Minute, 10*time.Minute)
	d2.RestoreSessions(sessions)
	if got := len(d2.AlertSessions()); got != 1 {
		t.Fatalf("还原后应有 1 个告警会话，got %d", got)
	}
	d2.Scan(now.Add(11 * time.Minute)) // 超过 alert_duration 无流量
	if got := len(d2.AlertSessions()); got != 0 {
		t.Fatalf("超时后告警会话应结束，got %d", got)
	}
}

// SetParams 应热更新触发阈值。
func TestDetectorSetParams(t *testing.T) {
	d, _ := newTestDetector(2, time.Minute, 10*time.Minute)
	now := time.Now()
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}, now)

	d.SetParams(5, time.Minute, 10*time.Minute) // 抬高阈值
	d.Scan(now)
	if snap := d.Snapshot(0); snap.Alerts != 0 {
		t.Fatalf("阈值=5 时不应告警，got alerts=%d", snap.Alerts)
	}

	d.SetParams(2, time.Minute, 10*time.Minute) // 降低阈值
	d.Scan(now)
	if snap := d.Snapshot(0); snap.Alerts != 1 {
		t.Fatalf("阈值=2 时应告警，got alerts=%d", snap.Alerts)
	}
}

// SetPeerLimit 应热更新单端口对端记录上限。
func TestDetectorSetPeerLimit(t *testing.T) {
	d, _ := newTestDetector(10, time.Minute, time.Hour)
	d.SetPeerLimit(3)
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000,
		[]string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"}, time.Now())

	snap := d.Snapshot(10)
	if len(snap.Devices) != 1 || len(snap.Devices[0].Ports) != 1 {
		t.Fatalf("设备/端口数不符：%+v", snap.Devices)
	}
	if got := snap.Devices[0].Ports[0].PeerCount; got != 3 {
		t.Fatalf("peer_limit=3 应只记录 3 个对端，got %d", got)
	}
}

// SetHide 应影响后续告警日志的地址掩码。
func TestDetectorSetHide(t *testing.T) {
	d, buf := newTestDetector(2, time.Minute, 10*time.Minute)
	now := time.Now()
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}, now)
	d.SetHide(true)
	d.Scan(now)
	if !strings.Contains(buf.String(), "...") {
		t.Fatalf("SetHide(true) 后告警日志应含掩码，got: %s", buf.String())
	}
}
func TestSetFilterHotSwap(t *testing.T) {
	d, _ := newTestDetector(2, time.Minute, 10*time.Minute)

	// 初始不过滤：应能记录设备。
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, []string{"1.1.1.1"}, time.Now())
	if devs, _ := d.Counts(); devs != 1 {
		t.Fatalf("未过滤时应记录 1 个设备，got %d", devs)
	}

	// 换成白名单（命中即不检测）：该 MAC 的流量应被忽略。
	f, err := filter.NewDeviceFilter(filter.ModeWhitelist, nil, []string{"aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("构建过滤器失败：%v", err)
	}
	d.SetFilter(f)
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40001, []string{"1.1.1.1"}, time.Now())
	if devs, _ := d.Counts(); devs != 1 {
		t.Fatalf("白名单内的新端口不应被记录，got %d", devs)
	}
}
