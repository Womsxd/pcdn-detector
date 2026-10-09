package detector

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/netutil"
)

func newTestDetector(threshold int, window, alertDuration time.Duration) (*Detector, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	return NewDetector(threshold, window, alertDuration, nil, logger, false), &buf
}

func observePeers(d *Detector, mac, ip string, port uint16, remoteIPs []string, ts time.Time) {
	observePeersFam(d, mac, ip, port, remoteIPs, ts, false)
}

func observePeersFam(d *Detector, mac, ip string, port uint16, remoteIPs []string, ts time.Time, v6 bool) {
	k, err := netutil.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	for _, rip := range remoteIPs {
		d.Observe(Observation{
			MAC: k, IP: netip.MustParseAddr(ip), LocalPort: port,
			RemoteIP: netip.MustParseAddr(rip),
			Up:       true, V6: v6, Proto: netutil.ProtoUDP, Length: 100, TS: ts,
		})
	}
}

// 同一 MAC 同时具备 IPv4/IPv6 地址时，各端口告警应输出与自身地址族一致的设备 IP。
func TestAlertDeviceIPMatchesAddressFamily(t *testing.T) {
	const mac = "60:21:01:1b:0a:23"
	const devV6 = "2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3"
	const devV4 = "192.168.1.100"

	d, buf := newTestDetector(2, time.Minute, 10*time.Minute)
	base := time.Now()

	// IPv6 端口。
	observePeersFam(d, mac, devV6, 1888, []string{
		"2408:8214:152d:3880:9d61:c8c9:ea36:551c",
		"2408:8214:891f:94b0:bcfb:96b1:f654:c234",
	}, base, true)
	d.Scan(base)
	if !strings.Contains(buf.String(), "("+devV6+") 的端口 1888") {
		t.Fatalf("IPv6 端口应显示 IPv6 设备 IP，got:\n%s", buf.String())
	}

	// IPv4 端口：不能被前面的 IPv6 设备 IP 覆盖。
	buf.Reset()
	observePeersFam(d, mac, devV4, 38924, []string{
		"112.245.115.51", "112.90.79.250",
	}, base.Add(time.Second), false)
	d.Scan(base.Add(time.Second))
	out := buf.String()
	if !strings.Contains(out, "("+devV4+") 的端口 38924") {
		t.Fatalf("IPv4 端口应显示 IPv4 设备 IP，got:\n%s", out)
	}
	if strings.Contains(out, devV6) {
		t.Fatalf("IPv4 端口告警不应出现 IPv6 设备 IP，got:\n%s", out)
	}
}

// 隐私模式下隐藏设备自身地址（IPv6/公网与 MAC），但保留设备外连的远端对端 IP。
func TestHideAddressMasksDeviceButNotPeers(t *testing.T) {
	const mac = "60:21:01:1b:0a:23"
	const devIP = "2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3"
	peers := []string{"2408:8214:152d:3880:9d61:c8c9:ea36:551c", "2409:8a1e:a691:70:8017:d5e8:30d4:8627"}

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	d := NewDetector(2, time.Minute, 10*time.Minute, nil, logger, true)
	base := time.Now()
	observePeersFam(d, mac, devIP, 1888, peers, base, true)
	d.Scan(base)

	out := buf.String()
	if !strings.Contains(out, "60:21:...:23(") {
		t.Fatalf("设备 MAC 应被掩码，got:\n%s", out)
	}
	if !strings.Contains(out, "2408:8240:...:b2a3") {
		t.Fatalf("设备 IPv6 应被掩码，got:\n%s", out)
	}
	if strings.Contains(out, devIP) || strings.Contains(out, mac) {
		t.Fatalf("不应出现完整设备地址或 MAC，got:\n%s", out)
	}
	for _, p := range peers {
		if !strings.Contains(out, p) {
			t.Fatalf("远端对端 IP %s 不应被隐藏，got:\n%s", p, out)
		}
	}
}

// 隐私模式下内网 IPv4 设备地址保留，公网远端对端不受影响。
func TestHideAddressKeepsPrivateDeviceIP(t *testing.T) {
	const mac = "60:21:01:1b:0a:23"
	const devIP = "192.168.1.100"

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	d := NewDetector(2, time.Minute, 10*time.Minute, nil, logger, true)
	base := time.Now()
	observePeers(d, mac, devIP, 40000, []string{"1.1.1.1", "2.2.2.2"}, base)
	d.Scan(base)

	out := buf.String()
	if !strings.Contains(out, "("+devIP+")") {
		t.Fatalf("内网 IPv4 设备地址不应被隐藏，got:\n%s", out)
	}
	if !strings.Contains(out, "60:21:...:23(") {
		t.Fatalf("设备 MAC 应被掩码，got:\n%s", out)
	}
	if !strings.Contains(out, "1.1.1.1") {
		t.Fatalf("远端对端 IP 不应被隐藏，got:\n%s", out)
	}
}

// IPv4 对端不应以 IPv4-mapped（::ffff:）形式输出，必须是纯 IPv4 点分十进制。
func TestAlertIPv4PeerNotMapped(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	d, buf := newTestDetector(2, time.Minute, 10*time.Minute)
	base := time.Now()
	observePeers(d, mac, ip, port, []string{"112.53.42.30", "112.90.79.250"}, base)
	d.Scan(base)

	out := buf.String()
	if strings.Contains(out, "::ffff:") {
		t.Fatalf("IPv4 对端不应带 ::ffff: 前缀，got:\n%s", out)
	}
	if !strings.Contains(out, "112.53.42.30") {
		t.Fatalf("应输出纯 IPv4 地址，got:\n%s", out)
	}
}

func TestAlertInitialThenContinuous(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	const ip = "192.168.1.100"
	const port = 40000

	d, buf := newTestDetector(3, time.Minute, 10*time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)
	if !strings.Contains(buf.String(), "疑似产生PCDN行为") {
		t.Fatalf("首次超阈值应输出疑似告警，got:\n%s", buf.String())
	}

	// 出现新 IP -> 持续告警，且只列出新增 IP。
	observePeers(d, mac, ip, port, []string{"4.4.4.4"}, base.Add(5*time.Second))
	buf.Reset()
	d.Scan(base.Add(5 * time.Second))
	out := buf.String()
	if !strings.Contains(out, "持续产生PCDN行为") || !strings.Contains(out, "4.4.4.4") {
		t.Fatalf("出现新 IP 应输出持续告警，got:\n%s", out)
	}

	// 没有新 IP -> 不再输出。
	buf.Reset()
	d.Scan(base.Add(10 * time.Second))
	if buf.Len() != 0 {
		t.Fatalf("无新 IP 不应再输出，got:\n%s", buf.String())
	}
}

func TestAlertEndAfterDurationAndReset(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	const ip = "192.168.1.100"
	const port = 40000

	d, buf := newTestDetector(3, 10*time.Minute, time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)

	// 超过 alertDuration 且期间完全没有任何流量：输出结束。
	idle := base.Add(2 * time.Minute)
	buf.Reset()
	d.Scan(idle)
	out := buf.String()
	if !strings.Contains(out, "PCDN行为结束") {
		t.Fatalf("持续时长内无任何流量应输出结束，got:\n%s", out)
	}
	if strings.Contains(out, "持续产生PCDN行为") {
		t.Fatalf("结束轮次不应输出持续告警，got:\n%s", out)
	}

	// 行为停止（对端超时清空）后重置，可再次触发。
	stop := base.Add(20 * time.Minute)
	d.Scan(stop)
	observePeers(d, mac, ip, port, []string{"6.6.6.6", "7.7.7.7", "8.8.8.8"}, stop)
	buf.Reset()
	d.Scan(stop)
	if !strings.Contains(buf.String(), "疑似产生PCDN行为") {
		t.Fatalf("重置后应能再次触发，got:\n%s", buf.String())
	}
}

// 持续期内即使只有旧对端（没有任何新 IP）持续流量，也应刷新计时器、不判结束。
// 旧实现仅在出现新对端 IP 时续期，本用例可防止其回归。
func TestContinuousOldPeerTrafficKeepsAlertAlive(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	// 窗口远大于 alertDuration，确保对端不会因超时被清掉。
	d, buf := newTestDetector(3, time.Hour, time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base) // 触发告警

	// 仅旧对端持续流量，无任何新 IP；间隔 40s（< alertDuration=1m）跨越 1m 多次。
	traffic := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for _, off := range []time.Duration{40 * time.Second, 80 * time.Second, 120 * time.Second} {
		at := base.Add(off)
		observePeers(d, mac, ip, port, traffic, at)
		buf.Reset()
		d.Scan(at)
		if strings.Contains(buf.String(), "PCDN行为结束") {
			t.Fatalf("旧对端持续流量时不应输出结束（t=+%s），got:\n%s", off, buf.String())
		}
		if strings.Contains(buf.String(), "持续产生PCDN行为") {
			t.Fatalf("无新对端时不应输出持续告警（t=+%s），got:\n%s", off, buf.String())
		}
	}
}

// 持续期内出现新对端会刷新计时器（滑动续期），因此超过原始 alertDuration 后仍能继续告警。
func TestAlertDurationRefreshedByNewPeer(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	d, buf := newTestDetector(3, 10*time.Minute, time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)

	// 50 秒时出现新对端 -> 计时器刷新到此刻。
	mid := base.Add(50 * time.Second)
	observePeers(d, mac, ip, port, []string{"4.4.4.4"}, mid)
	buf.Reset()
	d.Scan(mid)
	if !strings.Contains(buf.String(), "持续产生PCDN行为") {
		t.Fatalf("新对端应刷新并继续告警，got:\n%s", buf.String())
	}

	// 距首次触发已 80 秒（> alertDuration=1m），但距上次刷新仅 30 秒（< 1m），仍应告警。
	later := base.Add(80 * time.Second)
	observePeers(d, mac, ip, port, []string{"5.5.5.5"}, later)
	buf.Reset()
	d.Scan(later)
	if !strings.Contains(buf.String(), "持续产生PCDN行为") {
		t.Fatalf("计时器应被新对端刷新，got:\n%s", buf.String())
	}
}

// 持续期内窗口对端数跌破阈值时，单个新对端也应判定为仍在 PCDN。
func TestContinuousSingleNewPeerBelowThreshold(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	d, buf := newTestDetector(3, 30*time.Second, 10*time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)
	if !strings.Contains(buf.String(), "疑似产生PCDN行为") {
		t.Fatalf("首次应告警，got:\n%s", buf.String())
	}

	// 40 秒后旧对端全部超出窗口，仅剩 1 个新对端（数量 < 阈值）。
	later := base.Add(40 * time.Second)
	observePeers(d, mac, ip, port, []string{"4.4.4.4"}, later)
	buf.Reset()
	d.Scan(later)
	out := buf.String()
	if !strings.Contains(out, "持续产生PCDN行为") || !strings.Contains(out, "4.4.4.4") {
		t.Fatalf("持续期内单个新对端也应告警，got:\n%s", out)
	}
}

// 持续期内即使窗口内对端全部过期，随后出现的新对端仍应判定为持续 PCDN。
func TestContinuousAfterWindowEmptied(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	d, buf := newTestDetector(3, 30*time.Second, 10*time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)

	// 窗口内对端全部过期（count 归零），但仍在持续期，端口状态应保留。
	mid := base.Add(60 * time.Second)
	d.Scan(mid)
	observePeers(d, mac, ip, port, []string{"9.9.9.9"}, mid)
	buf.Reset()
	d.Scan(mid)
	if !strings.Contains(buf.String(), "持续产生PCDN行为") || !strings.Contains(buf.String(), "9.9.9.9") {
		t.Fatalf("窗口清空后持续期内新对端仍应告警，got:\n%s", buf.String())
	}
}

// 黑名单模式下只有名单内的设备会产生告警。
func TestDetectorBlacklistOnlyListed(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	f, err := filter.NewDeviceFilter(filter.ModeBlacklist, []string{"aa:bb:cc:dd:ee:ff"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDetector(2, time.Minute, 10*time.Minute, f, logger, false)
	base := time.Now()

	// 名单外设备：达到阈值也不应告警。
	observePeers(d, "11:22:33:44:55:66", "192.168.1.101", 40000, []string{"1.1.1.1", "2.2.2.2"}, base)
	d.Scan(base)
	if buf.Len() != 0 {
		t.Fatalf("名单外设备不应告警，got:\n%s", buf.String())
	}

	// 名单内设备：正常告警。
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.100", 40000, []string{"1.1.1.1", "2.2.2.2"}, base)
	d.Scan(base)
	if !strings.Contains(buf.String(), "疑似产生PCDN行为") {
		t.Fatalf("名单内设备应告警，got:\n%s", buf.String())
	}
}

type fakeSink struct {
	starts []string
	ends   []string
}

func (s *fakeSink) OnAlertStart(mac, ip string, port uint16, proto string) {
	s.starts = append(s.starts, fmt.Sprintf("%s:%d:%s", mac, port, proto))
}
func (s *fakeSink) OnAlertEnd(mac, ip string, port uint16, proto string) {
	s.ends = append(s.ends, fmt.Sprintf("%s:%d:%s", mac, port, proto))
}

// 检测层应在告警开始 / 结束时回调 sink。
func TestDetectorNotifiesSink(t *testing.T) {
	d, buf := newTestDetector(2, time.Minute, 10*time.Minute)
	sink := &fakeSink{}
	d.SetSink(sink)
	base := time.Now()

	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.100", 40000, []string{"1.1.1.1", "2.2.2.2"}, base)
	buf.Reset()
	d.Scan(base)
	if len(sink.starts) != 1 || sink.starts[0] != "aa:bb:cc:dd:ee:ff:40000:udp" {
		t.Fatalf("应回调告警开始，got %v", sink.starts)
	}

	// 超过 alertDuration 后本轮结束。
	d.Scan(base.Add(11 * time.Minute))
	if len(sink.ends) != 1 || sink.ends[0] != "aa:bb:cc:dd:ee:ff:40000:udp" {
		t.Fatalf("应回调告警结束，got %v", sink.ends)
	}
}

// BenchmarkDetectorRetainedBytesPerPeer 衡量进入告警（需记忆已提示对端）后，
// 每个对端在本程序侧占用的堆内存（字节），用于核对低内存优化效果。
// 运行：go test -run '^$' -bench RetainedBytesPerPeer -benchtime 3x
func BenchmarkDetectorRetainedBytesPerPeer(b *testing.B) {
	const n = 20000
	mac, _ := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	devIP := netip.MustParseAddr("192.168.1.100")
	base := time.Now()
	logger := log.New(io.Discard, "", 0)

	measured := false
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		d := NewDetector(1, time.Hour, time.Hour, nil, logger, false)
		for j := 0; j < n; j++ {
			d.Observe(Observation{
				MAC: mac, IP: devIP, LocalPort: 40000,
				RemoteIP: netip.AddrFrom4([4]byte{10, byte(j >> 16), byte(j >> 8), byte(j)}),
				Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
			})
		}
		d.Scan(base) // 触发告警：标记全部对端为已提示

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		// 仅取首次测量：后续迭代 before 可能已含上一轮尚未回收的数据。
		if !measured {
			b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/float64(n), "B/peer")
			measured = true
		}
		runtime.KeepAlive(d)
	}
}

// map 在明显缩小时应重建并保留全部存活元素。
func TestCompactMap(t *testing.T) {
	m := make(map[int]int)
	for i := 0; i < 1000; i++ {
		m[i] = i
	}
	for i := 10; i < 1000; i++ {
		delete(m, i)
	}

	// 峰值 1000、当前 10：10*4=40 ≤ 1000，应重建。
	nm, ok := compactMap(m, 1000)
	if !ok {
		t.Fatal("明显缩小时应重建 map")
	}
	if len(nm) != 10 {
		t.Fatalf("重建后应保留 10 个元素，got %d", len(nm))
	}
	for i := 0; i < 10; i++ {
		if v, exist := nm[i]; !exist || v != i {
			t.Fatalf("重建后元素丢失：nm[%d]=%d, exist=%v", i, v, exist)
		}
	}

	// 缩水不明显（当前 10、峰值 20）：不重建。
	if _, ok := compactMap(m, 20); ok {
		t.Fatal("缩水不明显时不应重建")
	}
	// 峰值低于阈值：不重建。
	if _, ok := compactMap(map[int]int{1: 1}, minCompactPeak-1); ok {
		t.Fatal("峰值低于阈值时不应重建")
	}
}

// 端口对端集合大幅缩小（大量对端过期）后，Scan 应重建该 map 以回收 bucket 内存。
func TestPeerMapCompactedAfterShrink(t *testing.T) {
	mac, _ := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	devIP := netip.MustParseAddr("192.168.1.100")
	base := time.Now()
	logger := log.New(io.Discard, "", 0)
	d := NewDetector(1, 10*time.Second, time.Hour, nil, logger, false)

	// 灌入 1000 个对端。
	for i := 0; i < 1000; i++ {
		d.Observe(Observation{
			MAC: mac, IP: devIP, LocalPort: 40000,
			RemoteIP: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
			Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
		})
	}
	ps := d.devices[mac].ports[portKey{port: 40000, proto: netutil.ProtoUDP}]
	if ps == nil {
		t.Fatal("端口状态未建立")
	}

	// 仅保留 5 个对端（用新时间戳刷新），其余在窗口外过期。
	later := base.Add(30 * time.Second) // > window(10s)
	for i := 0; i < 5; i++ {
		d.Observe(Observation{
			MAC: mac, IP: devIP, LocalPort: 40000,
			RemoteIP: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}),
			Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: later,
		})
	}
	d.Scan(later)

	if ps.numPeers() != 5 {
		t.Fatalf("过期清理后应剩 5 个对端，got %d", ps.numPeers())
	}
	// 峰值被重置为存活数，说明 map 确已重建（未重建则仍为 1000）。
	if ps.peersPeak != 5 {
		t.Fatalf("对端 map 应被重建（峰值重置为 5），got %d", ps.peersPeak)
	}
}

// 设备 map 大幅缩小（大量设备下线）后，Scan 应重建该 map 以回收 bucket 内存。
func TestDevicesMapCompactedAfterShrink(t *testing.T) {
	base := time.Now()
	logger := log.New(io.Discard, "", 0)
	d := NewDetector(1, 10*time.Second, time.Hour, nil, logger, false)

	macs := make([]netutil.MAC, 100)
	for i := range macs {
		macs[i] = netutil.MAC{0x02, 0, 0, 0, byte(i >> 8), byte(i)}
		d.Observe(Observation{
			MAC: macs[i], IP: netip.MustParseAddr("192.168.1.100"), LocalPort: 40000,
			RemoteIP: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}),
			Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
		})
	}
	if len(d.devices) != 100 {
		t.Fatalf("应跟踪 100 个设备，got %d", len(d.devices))
	}

	// 仅刷新前 5 个设备，其余因端口全部过期而被移除。
	later := base.Add(30 * time.Second)
	for i := 0; i < 5; i++ {
		d.Observe(Observation{
			MAC: macs[i], IP: netip.MustParseAddr("192.168.1.100"), LocalPort: 40000,
			RemoteIP: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}),
			Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: later,
		})
	}
	d.Scan(later)

	if len(d.devices) != 5 {
		t.Fatalf("过期清理后应剩 5 个设备，got %d", len(d.devices))
	}
	if d.devicesPeak != 5 {
		t.Fatalf("设备 map 应被重建（峰值重置为 5），got %d", d.devicesPeak)
	}
}

// BenchmarkDetectorMapShrinkReclaim 衡量对端集合在大量过期后经 map 重建回收的堆内存。
// 运行：go test -run '^$' -bench MapShrinkReclaim -benchtime 3x
func BenchmarkDetectorMapShrinkReclaim(b *testing.B) {
	const n = 20000
	mac, _ := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	devIP := netip.MustParseAddr("192.168.1.100")
	base := time.Now()
	logger := log.New(io.Discard, "", 0)

	measured := false
	for i := 0; i < b.N; i++ {
		d := NewDetector(1, 10*time.Second, time.Hour, nil, logger, false)
		for j := 0; j < n; j++ {
			d.Observe(Observation{
				MAC: mac, IP: devIP, LocalPort: 40000,
				RemoteIP: netip.AddrFrom4([4]byte{10, byte(j >> 16), byte(j >> 8), byte(j)}),
				Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
			})
		}
		// 仅刷新 1 个对端，其余全部过期，触发对端 map 重建。
		later := base.Add(time.Minute)
		d.Observe(Observation{
			MAC: mac, IP: devIP, LocalPort: 40000,
			RemoteIP: netip.AddrFrom4([4]byte{10, 0, 0, 0}),
			Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: later,
		})

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		d.Scan(later)

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if !measured {
			b.ReportMetric(float64(int64(before.HeapAlloc)-int64(after.HeapAlloc))/1024, "KiB_reclaimed")
			measured = true
		}
		runtime.KeepAlive(d)
	}
}
