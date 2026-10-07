package main

import (
	"bytes"
	"log"
	"net/netip"
	"strings"
	"testing"
	"time"
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
	k, err := parseMACKey(mac)
	if err != nil {
		panic(err)
	}
	for _, rip := range remoteIPs {
		d.Observe(observation{
			mac: k, ip: netip.MustParseAddr(ip), localPort: port,
			remoteIP: netip.MustParseAddr(rip),
			up:       true, v6: v6, length: 100, ts: ts,
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

func TestMaskAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"60:21:01:1b:0a:23", "60:21:...:23"},
		{"2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", "2408:8240:...:b2a3"},
		{"112.245.115.51", "112.*.*.51"},
		{"1.2.3", "1.2.3"},
		{"", ""},
	}
	for _, c := range cases {
		if got := maskAddress(c.in); got != c.want {
			t.Errorf("maskAddress(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestShouldMaskDeviceIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"2408:8240:9411:37b0:4e9:adaa:3a1a:b2a3", true}, // 公网 IPv6
		{"fe80::1", true},        // 链路本地 IPv6 也隐藏
		{"8.8.8.8", true},        // 公网 IPv4
		{"192.168.1.100", false}, // 内网 IPv4 保留
		{"10.0.0.1", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := shouldMaskDeviceIP(c.ip); got != c.want {
			t.Errorf("shouldMaskDeviceIP(%q) = %v，期望 %v", c.ip, got, c.want)
		}
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

	// 超过 alertDuration 没有新对端：输出结束且不再有持续告警。
	late := base.Add(2 * time.Minute)
	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "5.5.5.5"}, late)
	buf.Reset()
	d.Scan(late)
	out := buf.String()
	if !strings.Contains(out, "PCDN行为结束") {
		t.Fatalf("超过持续时长应输出结束，got:\n%s", out)
	}
	if strings.Contains(out, "持续产生PCDN行为") {
		t.Fatalf("超过持续时长不应再输出持续告警，got:\n%s", out)
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
	f, err := NewDeviceFilter(listModeBlacklist, []string{"aa:bb:cc:dd:ee:ff"}, nil)
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
