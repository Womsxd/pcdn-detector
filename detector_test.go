package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func newTestDetector(threshold int, window, alertDuration time.Duration) (*Detector, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	return NewDetector(threshold, window, alertDuration, logger), &buf
}

func observePeers(d *Detector, mac, ip string, port uint16, remoteIPs []string, ts time.Time) {
	observePeersFam(d, mac, ip, port, remoteIPs, ts, false)
}

func observePeersFam(d *Detector, mac, ip string, port uint16, remoteIPs []string, ts time.Time, v6 bool) {
	for _, rip := range remoteIPs {
		d.Observe(observation{
			mac: mac, ip: ip, localPort: port,
			remoteIP: rip, remotePort: 1234,
			up: true, v6: v6, length: 100, ts: ts,
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

func TestAlertSilentAfterDurationAndReset(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	const ip = "192.168.1.100"
	const port = 40000

	d, buf := newTestDetector(3, 10*time.Minute, time.Minute)
	base := time.Now()

	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, base)
	d.Scan(base)

	// 超过 alertDuration 后，即使出现新 IP 也应静默。
	late := base.Add(2 * time.Minute)
	observePeers(d, mac, ip, port, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "5.5.5.5"}, late)
	buf.Reset()
	d.Scan(late)
	if strings.Contains(buf.String(), "持续产生PCDN行为") {
		t.Fatalf("超过持续时长应静默，got:\n%s", buf.String())
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
