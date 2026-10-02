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
	for _, rip := range remoteIPs {
		d.Observe(observation{
			mac: mac, ip: ip, localPort: port,
			remoteIP: rip, remotePort: 1234,
			up: true, length: 100, ts: ts,
		})
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
