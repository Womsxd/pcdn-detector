package detector

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/logx"
	"pcdn-detect/internal/netutil"
)

func newTestDetector(threshold int, window, alertDuration time.Duration) (*Detector, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	return NewDetector(threshold, window, alertDuration, nil, logger, false, false, 0, 0), &buf
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
	logger := logx.New(&buf, "", 0)
	d := NewDetector(2, time.Minute, 10*time.Minute, nil, logger, true, false, 0, 0)
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
	logger := logx.New(&buf, "", 0)
	d := NewDetector(2, time.Minute, 10*time.Minute, nil, logger, true, false, 0, 0)
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
	logger := logx.New(&buf, "", 0)
	f, err := filter.NewDeviceFilter(filter.ModeBlacklist, []string{"aa:bb:cc:dd:ee:ff"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDetector(2, time.Minute, 10*time.Minute, f, logger, false, false, 0, 0)
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

// 低内存模式：端口触发告警后应清空对端列表、不再记录新对端，仅保留触发状态；
// 告警期间有流量则续期且不输出持续告警，结束后恢复正常统计并可再次触发。
func TestLowMemoryModeClearsPeersAndStopsRecording(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	d := NewDetector(3, time.Minute, time.Minute, nil, logger, false, true, 0, 0)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)
	if !strings.Contains(buf.String(), "疑似产生PCDN行为") {
		t.Fatalf("首次超阈值应输出疑似告警，got:\n%s", buf.String())
	}

	k, err := netutil.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	key := portKey{port: port, proto: netutil.ProtoUDP}
	ps := d.devices[k].v4.m[key]
	if ps == nil {
		t.Fatal("端口状态未建立")
	}
	// 触发后对端列表应被清空（内联槽位与 map 都释放），仅保留触发状态。
	if ps.peers.large != nil || ps.peers.count() != 0 {
		t.Fatalf("触发后应清空对端列表，got large!=nil=%v n=%d", ps.peers.large != nil, ps.peers.count())
	}
	if ps.alertStartNano == 0 {
		t.Fatal("触发后应保留告警状态")
	}

	// 持续期内仍有流量：即使出现新对端 IP 也不再记录（数量保持 0），
	// 仍应因流量续期而不判结束；也不应输出「持续产生PCDN行为」。
	later := base.Add(40 * time.Second)
	observePeers(d, mac, ip, port, []string{"4.4.4.4", "5.5.5.5"}, later)
	buf.Reset()
	d.Scan(later)
	if ps.peers.count() != 0 {
		t.Fatalf("低内存模式下告警期间不应再记录对端，got %d", ps.peers.count())
	}
	out := buf.String()
	if strings.Contains(out, "PCDN行为结束") {
		t.Fatalf("仍有流量时不应判结束，got:\n%s", out)
	}
	if strings.Contains(out, "持续产生PCDN行为") {
		t.Fatalf("低内存模式下不应输出持续告警，got:\n%s", out)
	}

	// 超过 alertDuration 且期间无流量：结束本轮。
	idle := later.Add(2 * time.Minute)
	buf.Reset()
	d.Scan(idle)
	if !strings.Contains(buf.String(), "PCDN行为结束") {
		t.Fatalf("长时间无流量应输出结束，got:\n%s", buf.String())
	}

	// 结束后恢复正常统计，可再次触发。
	observePeers(d, mac, ip, port, []string{"6.6.6.6", "7.7.7.7", "8.8.8.8"}, idle)
	buf.Reset()
	d.Scan(idle)
	if !strings.Contains(buf.String(), "疑似产生PCDN行为") {
		t.Fatalf("结束后应能再次触发，got:\n%s", buf.String())
	}
}

// 对端记录上限：达到上限后不再记录新对端，已有对端不受影响，端口级流量仍完整累计。
func TestPeerLimitCapsRecords(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)

	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	// 阈值 3，对端上限 5。
	d := NewDetector(3, time.Minute, time.Hour, nil, logger, false, false, 5, 0)
	base := time.Now()

	k, err := netutil.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}

	// 灌入 8 个对端（超过上限 5）：对端记录应被限制为 5。
	for i := 0; i < 8; i++ {
		observePeers(d, mac, ip, port, []string{fmt.Sprintf("10.0.0.%d", i+1)}, base)
	}
	key := portKey{port: port, proto: netutil.ProtoUDP}
	ps := d.devices[k].v4.m[key]
	if ps == nil {
		t.Fatal("端口状态未建立")
	}
	if ps.peers.count() != 5 {
		t.Fatalf("对端记录应被上限限制为 5，got %d", ps.peers.count())
	}
	// 端口级流量应累计全部 8 个报文（每个 100 字节上行），不受对端上限影响。
	if ps.upBytes != 8*100 {
		t.Fatalf("端口级上行流量应累计全部报文 800，got %d", ps.upBytes)
	}

	// 上限为 0 时不限制：全部记录。
	buf.Reset()
	d2 := NewDetector(3, time.Minute, time.Hour, nil, logger, false, false, 0, 0)
	for i := 0; i < 8; i++ {
		observePeers(d2, mac, ip, port, []string{fmt.Sprintf("10.0.0.%d", i+1)}, base)
	}
	ps2 := d2.devices[k].v4.m[key]
	if ps2.peers.count() != 8 {
		t.Fatalf("上限为 0 时不应限制对端数量，got %d", ps2.peers.count())
	}
}

// 端口上限：达到上限后按「剩余寿命档位 → 对端数」批量提前过期，为新端口腾出位置。
func TestMaxPortsEvictsNearExpiryLowPeers(t *testing.T) {
	const mac, ip = "aa:bb:cc:dd:ee:ff", "192.168.1.100"
	const maxPorts = 20

	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	d := NewDetector(3, time.Minute, time.Hour, nil, logger, false, false, 0, maxPorts)

	now := time.Now()
	old := now.Add(-59 * time.Second) // 剩余 1s：0 档（最接近过期）
	k, err := netutil.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	devIP := netip.MustParseAddr(ip)
	observe := func(port uint16, ts time.Time, peers ...string) {
		for _, p := range peers {
			d.Observe(Observation{
				MAC: k, IP: devIP, LocalPort: port, RemoteIP: netip.MustParseAddr(p),
				Up: true, Proto: netutil.ProtoUDP, Length: 100, TS: ts,
			})
		}
	}

	// 0 档三个端口：对端数分别为 1 / 3 / 2；其余 17 个端口刚活跃（9 档），各 1 个对端。
	observe(40000, old, "1.1.1.1")
	observe(40001, old, "1.1.1.2", "1.1.1.3", "1.1.1.4")
	observe(40002, old, "1.1.1.5", "1.1.1.6")
	for p := uint16(40003); p < 40000+maxPorts; p++ {
		observe(p, now, "2.2.2.1")
	}
	if got := len(d.devices[k].v4.m); got != maxPorts {
		t.Fatalf("应建立 %d 个端口，got %d", maxPorts, got)
	}

	// 新增端口：淘汰 0 档中对端最少的 2 个（40000 与 40002），40001（3 个对端）保留。
	observe(40020, now, "3.3.3.1")

	dev := d.devices[k]
	// 一次批量淘汰 10%（2 个）后再新增 1 个：20 - 2 + 1 = 19。
	if got := len(dev.v4.m); got != maxPorts-2+1 {
		t.Fatalf("批量淘汰后端口数应为 %d，got %d", maxPorts-2+1, got)
	}
	for _, p := range []uint16{40000, 40002} {
		if _, ok := dev.v4.m[portKey{port: p, proto: netutil.ProtoUDP}]; ok {
			t.Fatalf("端口 %d 应被提前过期", p)
		}
	}
	for _, p := range []uint16{40001, 40003, 40020} {
		if _, ok := dev.v4.m[portKey{port: p, proto: netutil.ProtoUDP}]; !ok {
			t.Fatalf("端口 %d 不应被提前过期", p)
		}
	}
	if d.portEvictions != 2 {
		t.Fatalf("应累计提前过期 2 个端口，got %d", d.portEvictions)
	}
}

// 端口上限：处于告警中的端口不参与提前过期。
func TestMaxPortsSkipsAlertingPorts(t *testing.T) {
	const mac, ip = "aa:bb:cc:dd:ee:ff", "192.168.1.100"

	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	d := NewDetector(2, time.Minute, time.Hour, nil, logger, false, false, 0, 2)
	base := time.Now()

	// 端口 40000 触发告警。
	observePeers(d, mac, ip, 40000, []string{"1.1.1.1", "1.1.1.2"}, base)
	d.Scan(base)
	k, _ := netutil.ParseMAC(mac)
	if ps := d.devices[k].v4.m[portKey{port: 40000, proto: netutil.ProtoUDP}]; ps == nil || ps.alertStartNano == 0 {
		t.Fatal("端口 40000 应处于告警中")
	}

	// 端口 40001 未告警；新增 40002 时只能淘汰它。
	observePeers(d, mac, ip, 40001, []string{"2.2.2.1"}, base)
	observePeers(d, mac, ip, 40002, []string{"3.3.3.1"}, base)

	dev := d.devices[k]
	if _, ok := dev.v4.m[portKey{port: 40000, proto: netutil.ProtoUDP}]; !ok {
		t.Fatal("告警中的端口不应被提前过期")
	}
	if _, ok := dev.v4.m[portKey{port: 40001, proto: netutil.ProtoUDP}]; ok {
		t.Fatal("未告警的端口应被提前过期")
	}
	if _, ok := dev.v4.m[portKey{port: 40002, proto: netutil.ProtoUDP}]; !ok {
		t.Fatal("新端口应被建立")
	}
	if d.portEvictions != 1 || d.portDrops != 0 {
		t.Fatalf("应只提前过期 1 个端口且无丢弃，got evictions=%d drops=%d", d.portEvictions, d.portDrops)
	}
}

// 端口上限：全部端口都在告警中时无处腾挪，新端口不建立并计数、日志提示（首次）。
func TestMaxPortsDropsWhenAllAlerting(t *testing.T) {
	const mac, ip = "aa:bb:cc:dd:ee:ff", "192.168.1.100"

	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	d := NewDetector(2, time.Minute, time.Hour, nil, logger, false, false, 0, 1)
	base := time.Now()

	observePeers(d, mac, ip, 40000, []string{"1.1.1.1", "1.1.1.2"}, base)
	d.Scan(base) // 40000 进入告警
	buf.Reset()
	observePeers(d, mac, ip, 40001, []string{"2.2.2.1"}, base)

	k, _ := netutil.ParseMAC(mac)
	dev := d.devices[k]
	if _, ok := dev.v4.m[portKey{port: 40001, proto: netutil.ProtoUDP}]; ok {
		t.Fatal("无可淘汰端口时不应建立新端口")
	}
	if d.portDrops != 1 {
		t.Fatalf("应累计丢弃 1 个新端口报文，got %d", d.portDrops)
	}
	if !strings.Contains(buf.String(), "达到上限") {
		t.Fatalf("首次丢弃应输出提示日志，got:\n%s", buf.String())
	}
}

// 端口上限：上限被调小后，由 Scan 把超出的端口收敛到新上限。
func TestMaxPortsLoweredTrimmedOnScan(t *testing.T) {
	const mac, ip = "aa:bb:cc:dd:ee:ff", "192.168.1.100"

	var buf bytes.Buffer
	logger := logx.New(&buf, "", 0)
	// 阈值设高一些，避免 Scan 把各端口判成告警（告警中的端口不参与淘汰）。
	d := NewDetector(5, time.Minute, time.Hour, nil, logger, false, false, 0, 0) // 先不限制
	base := time.Now()

	for p := uint16(40000); p < 40010; p++ {
		observePeers(d, mac, ip, p, []string{"1.1.1.1"}, base)
	}
	d.SetMaxPorts(4)
	d.Scan(base)

	k, _ := netutil.ParseMAC(mac)
	if got := len(d.devices[k].v4.m); got != 4 {
		t.Fatalf("Scan 后端口数应收敛为 4，got %d", got)
	}
	if d.portEvictions != 6 {
		t.Fatalf("应累计提前过期 6 个端口，got %d", d.portEvictions)
	}
}

// expiryBucket：按窗口均分 10 档，0 = 最接近过期，最后一档 = 最近活跃。
func TestExpiryBucket(t *testing.T) {
	const w = int64(time.Minute)
	cases := []struct {
		lastActive int64
		window     int64
		want       int
	}{
		{0, w, expiryBuckets - 1},         // 刚刚活跃：剩余整窗口
		{-int64(6 * time.Second), w, 9},   // 剩余 54s
		{-int64(7 * time.Second), w, 8},   // 剩余 53s
		{-int64(55 * time.Second), w, 0},  // 剩余 5s
		{-int64(60 * time.Second), w, 0},  // 恰好过期
		{-int64(100 * time.Second), w, 0}, // 已过期
		{0, 0, 0},                         // 窗口非法时保守归 0 档
	}
	for _, c := range cases {
		if got := expiryBucket(0, c.lastActive, c.window); got != c.want {
			t.Errorf("expiryBucket(now=0, last=%d, window=%d)=%d，期望 %d", c.lastActive, c.window, got, c.want)
		}
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
	logger := logx.New(io.Discard, "", 0)

	measured := false
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		d := NewDetector(1, time.Hour, time.Hour, nil, logger, false, false, 0, 0)
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

// 单对端端口（客户端式临时端口最常见的形态）不应为对端集合分配 map。
func TestSinglePeerPortStaysInline(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)
	d, _ := newTestDetector(10, time.Minute, time.Hour)
	base := time.Now()

	k, err := netutil.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	key := portKey{port: port, proto: netutil.ProtoUDP}

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for i, rip := range ips {
		observePeers(d, mac, ip, port, []string{rip}, base)
		ps := d.devices[k].v4.m[key]
		if ps == nil {
			t.Fatal("端口状态未建立")
		}
		if ps.peers.large != nil {
			t.Fatalf("不超过 %d 个对端时不应分配 map（已有 %d 个）", inlinePeers, i+1)
		}
		if got := ps.peers.count(); got != i+1 {
			t.Fatalf("对端数应为 %d，got %d", i+1, got)
		}
	}

	// 第 5 个对端触发升级：已有对端全部保留。
	observePeers(d, mac, ip, port, []string{"5.5.5.5"}, base)
	ps := d.devices[k].v4.m[key]
	if ps.peers.large == nil {
		t.Fatalf("超过 %d 个对端后应升级为 map", inlinePeers)
	}
	if got := ps.peers.count(); got != len(ips)+1 {
		t.Fatalf("升级后应保留全部 %d 个对端，got %d", len(ips)+1, got)
	}
}

// 升级为 map 后即使对端大幅减少也保留 map（不再退回内联），存活对端及其「已提示」标记
// 均不受影响；只有端口彻底空闲被删除时 map 才随之释放。
func TestPeerMapRetainedAfterShrink(t *testing.T) {
	const mac, ip, port = "aa:bb:cc:dd:ee:ff", "192.168.1.100", uint16(40000)
	d, buf := newTestDetector(5, 10*time.Second, time.Hour)
	base := time.Now()

	k, err := netutil.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	key := portKey{port: port, proto: netutil.ProtoUDP}

	burst := make([]string, 10)
	for i := range burst {
		burst[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	observePeers(d, mac, ip, port, burst, base)
	d.Scan(base) // 触发告警：全部对端标记为已提示
	ps := d.devices[k].v4.m[key]
	if ps == nil || ps.peers.large == nil {
		t.Fatal("10 个对端时应已升级为 map")
	}

	// 窗口过后只剩 2 个新对端（其余全部过期）：map 应保留，存活对端与标记不受影响。
	later := base.Add(30 * time.Second) // > window(10s)
	observePeers(d, mac, ip, port, []string{"9.9.9.1", "9.9.9.2"}, later)
	buf.Reset()
	d.Scan(later)

	if ps.peers.large == nil {
		t.Fatal("升级为 map 后不应退回内联存储")
	}
	if got := ps.peers.count(); got != 2 {
		t.Fatalf("过期清理后应剩 2 个对端，got %d", got)
	}
	if !strings.Contains(buf.String(), "9.9.9.1") {
		t.Fatalf("新对端应输出持续告警，got:\n%s", buf.String())
	}

	// 「已提示」标记仍应保留：再次扫描不应重复告警。
	buf.Reset()
	d.Scan(later.Add(time.Second))
	if strings.Contains(buf.String(), "持续产生PCDN行为") {
		t.Fatalf("已提示过的对端不应重复告警，got:\n%s", buf.String())
	}
}

// BenchmarkDetectorRetainedBytesPerIdlePort 衡量「每个端口只记录 1 个对端」这一最常见形态下
// 单个空闲端口的堆占用（字节），用于核对内联小对端集合（不为单对端端口分配 map）的效果。
// 运行：go test -run '^$' -bench RetainedBytesPerIdlePort -benchtime 3x
func BenchmarkDetectorRetainedBytesPerIdlePort(b *testing.B) {
	const ports = 5000
	mac, _ := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	devIP := netip.MustParseAddr("192.168.1.100")
	base := time.Now()
	logger := logx.New(io.Discard, "", 0)

	measured := false
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		d := NewDetector(10, time.Hour, time.Hour, nil, logger, false, false, 0, 0)
		for p := 0; p < ports; p++ {
			d.Observe(Observation{
				MAC: mac, IP: devIP, LocalPort: uint16(10000 + p),
				RemoteIP: netip.AddrFrom4([4]byte{10, byte(p >> 16), byte(p >> 8), byte(p)}),
				Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
			})
		}

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if !measured {
			b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/float64(ports), "B/port")
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
	logger := logx.New(io.Discard, "", 0)
	d := NewDetector(1, 10*time.Second, time.Hour, nil, logger, false, false, 0, 0)

	// 灌入 1000 个对端。
	for i := 0; i < 1000; i++ {
		d.Observe(Observation{
			MAC: mac, IP: devIP, LocalPort: 40000,
			RemoteIP: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
			Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
		})
	}
	key := portKey{port: 40000, proto: netutil.ProtoUDP}
	ps := d.devices[mac].v4.m[key]
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

	if ps.peers.count() != 5 {
		t.Fatalf("过期清理后应剩 5 个对端，got %d", ps.peers.count())
	}
	// 峰值被重置为存活数，说明 map 确已重建（未重建则仍为 1000）。
	if ps.peers.peak != 5 {
		t.Fatalf("对端 map 应被重建（峰值重置为 5），got %d", ps.peers.peak)
	}
}

// 设备 map 大幅缩小（大量设备下线）后，Scan 应重建该 map 以回收 bucket 内存。
func TestDevicesMapCompactedAfterShrink(t *testing.T) {
	base := time.Now()
	logger := logx.New(io.Discard, "", 0)
	d := NewDetector(1, 10*time.Second, time.Hour, nil, logger, false, false, 0, 0)

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
	logger := logx.New(io.Discard, "", 0)

	measured := false
	for i := 0; i < b.N; i++ {
		d := NewDetector(1, 10*time.Second, time.Hour, nil, logger, false, false, 0, 0)
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

// SetFilter 可在运行时热替换（reload），与抓包热路径的 Observe 并发执行；
// 本用例在 -race 下必须通过：Observe 读过滤器不得与 SetFilter 的写构成数据竞争。
func TestObserveConcurrentWithSetFilter(t *testing.T) {
	d, _ := newTestDetector(3, time.Minute, time.Minute)
	mac, err := netutil.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("解析 MAC 失败：%v", err)
	}
	allow, err := filter.NewDeviceFilter(filter.ModeWhitelist, nil, nil) // 空白名单：全部放行
	if err != nil {
		t.Fatalf("构建过滤器失败：%v", err)
	}
	deny, err := filter.NewDeviceFilter(filter.ModeBlacklist, nil, nil) // 空黑名单：全部丢弃
	if err != nil {
		t.Fatalf("构建过滤器失败：%v", err)
	}
	d.SetFilter(allow)

	base := time.Now()
	const rounds = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			d.Observe(Observation{
				MAC: mac, IP: netip.MustParseAddr("192.168.1.9"), LocalPort: 40000,
				RemoteIP: netip.AddrFrom4([4]byte{1, 1, 1, byte(i)}),
				Up:       true, Proto: netutil.ProtoUDP, Length: 100, TS: base,
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if i%2 == 0 {
				d.SetFilter(deny)
				continue
			}
			d.SetFilter(allow)
		}
	}()
	wg.Wait()

	// 热替换应即时生效：替换为「全部丢弃」后，新设备不再进入跟踪。
	devices, _ := d.Counts()
	d.SetFilter(deny)
	observePeers(d, "11:22:33:44:55:66", "192.168.1.10", 40001, []string{"5.5.5.5"}, base)
	if got, _ := d.Counts(); got != devices {
		t.Fatalf("替换为丢弃型过滤器后仍跟踪了新设备：before=%d after=%d", devices, got)
	}
}

// 单个端口对端很多时，告警日志只列前 alertLogMaxIPs 个并注明总数：
// 避免 logd / 串口被刷屏，也避免在持锁期间格式化数万个 IP。
func TestAlertLogTruncatesPeers(t *testing.T) {
	d, buf := newTestDetector(2, time.Minute, time.Minute)
	peers := make([]string, 0, 100)
	for i := 1; i <= 100; i++ {
		peers = append(peers, fmt.Sprintf("10.0.0.%d", i))
	}
	base := time.Now()
	observePeers(d, "aa:bb:cc:dd:ee:ff", "192.168.1.2", 40000, peers, base)
	d.Scan(base)

	out := buf.String()
	if !strings.Contains(out, "共 100 个") || !strings.Contains(out, "仅列前 20 个") {
		t.Fatalf("日志应注明总数与展示上限，got:\n%s", out)
	}
	if strings.Contains(out, "10.0.0.21") {
		t.Fatalf("第 %d 个之后的对端不应出现在日志中，got:\n%s", alertLogMaxIPs, out)
	}
	if len(out) >= 2048 {
		t.Fatalf("单条告警日志过大（%d 字节），got:\n%s", len(out), out)
	}
}

// /peers 的 limit 语义是「只要前 N 个」：返回数量、truncated 与真实总数必须正确，
// 且排序按地址数值序（IPv6 的字符串序与数值序不同）。
func TestPeersTruncatesToLimit(t *testing.T) {
	d, _ := newTestDetector(2, time.Minute, time.Minute)
	base := time.Now()
	const mac = "aa:bb:cc:dd:ee:ff"
	peers := make([]string, 0, 200)
	for i := 1; i <= 200; i++ {
		peers = append(peers, fmt.Sprintf("10.0.0.%d", i))
	}
	observePeers(d, mac, "192.168.1.2", 40000, peers, base)

	macKey, err := netutil.ParseMAC(mac)
	if err != nil {
		t.Fatalf("解析 MAC 失败：%v", err)
	}
	pv, ok := d.Peers(macKey, 40000, netutil.ProtoUDP, false, 10)
	if !ok {
		t.Fatal("应能查到该端口的对端列表")
	}
	if !pv.Truncated || len(pv.PeerIPs) != 10 || pv.PeerCount != 200 {
		t.Fatalf("对端列表不符：truncated=%v len=%d count=%d", pv.Truncated, len(pv.PeerIPs), pv.PeerCount)
	}
	for i, ip := range pv.PeerIPs {
		if want := fmt.Sprintf("10.0.0.%d", i+1); ip != want {
			t.Fatalf("第 %d 个对端应为 %s，got %s（完整列表 %v）", i+1, want, ip, pv.PeerIPs)
		}
	}

	// IPv6：字符串序会把 "2001:db8::10" 排在 "2001:db8::2" 之前，数值序则相反。
	observePeersFam(d, mac, "2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", 40001,
		[]string{"2001:db8::10", "2001:db8::2"}, base, true)
	pv6, ok := d.Peers(macKey, 40001, netutil.ProtoUDP, true, 0)
	if !ok {
		t.Fatal("应能查到该 IPv6 端口的对端列表")
	}
	if pv6.Truncated || len(pv6.PeerIPs) != 2 || pv6.PeerIPs[0] != "2001:db8::2" {
		t.Fatalf("IPv6 对端应按数值序返回：%+v", pv6)
	}
}
