package main

import (
	"io"
	"log"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/httpapi"
)

// 重载期间的重复 SIGHUP 应合并为一次；SIGTERM 仍能正常触发退出（不被 SIGHUP 挤掉）。
func TestHandleSignalsCoalescesHUP(t *testing.T) {
	hup := make(chan os.Signal, 1)
	term := make(chan os.Signal, 1)

	first := make(chan struct{})
	release := make(chan struct{})
	var reloads int32
	reload := func() (httpapi.ReloadResult, error) {
		if atomic.AddInt32(&reloads, 1) == 1 {
			close(first)
			<-release
		}
		return httpapi.ReloadResult{Applied: []string{"detect"}}, nil
	}
	canceled := make(chan struct{})
	go handleSignals(hup, term, reload, log.New(io.Discard, "", 0), func() { close(canceled) })

	hup <- syscall.SIGHUP
	<-first // 第一次 reload 已开始并阻塞

	// 重载期间连续两次 SIGHUP：一个进入容量为 1 的缓冲，另一个按内核语义被丢弃。
	select {
	case hup <- syscall.SIGHUP:
	default:
	}
	select {
	case hup <- syscall.SIGHUP:
	default:
	}
	close(release)

	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&reloads); got != 1 {
		t.Fatalf("重载期间的重复 SIGHUP 应合并为一次，got %d 次", got)
	}

	term <- syscall.SIGTERM
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("SIGTERM 应触发退出")
	}
}

// reload 时 [capture] protocol 变化也要重建防火墙：它决定 nftables 预建的协议集合，
// 不重建会使新协议（如 udp → all 后的 TCP）的封禁命令因集合不存在而全部失败。
func TestFirewallNeedsRebuildOnProtocolChange(t *testing.T) {
	enabled := *config.DefaultConfig()
	enabled.Firewall.Enabled = true

	cases := []struct {
		name string
		old  config.Config
		new  config.Config
		want bool
	}{
		{
			name: "启用时 udp → all",
			old:  withProto(enabled, config.ProtoModeUDP),
			new:  withProto(enabled, config.ProtoModeAll),
			want: true,
		},
		{
			name: "启用时 all → udp",
			old:  withProto(enabled, config.ProtoModeAll),
			new:  withProto(enabled, config.ProtoModeUDP),
			want: true,
		},
		{
			name: "启用时 tcp → udp",
			old:  withProto(enabled, config.ProtoModeTCP),
			new:  withProto(enabled, config.ProtoModeUDP),
			want: true,
		},
		{
			name: "启用时协议不变",
			old:  withProto(enabled, config.ProtoModeAll),
			new:  withProto(enabled, config.ProtoModeAll),
			want: false,
		},
		{
			name: "启用时仅 snaplen 变化",
			old:  withSnaplen(withProto(enabled, config.ProtoModeAll), 512),
			new:  withProto(enabled, config.ProtoModeAll),
			want: false,
		},
		{
			name: "禁用时协议变化无需重建",
			old:  withProto(*config.DefaultConfig(), config.ProtoModeUDP),
			new:  withProto(*config.DefaultConfig(), config.ProtoModeAll),
			want: false,
		},
		{
			name: "防火墙配置变化仍需重建",
			old:  withProto(*config.DefaultConfig(), config.ProtoModeUDP),
			new:  withProto(enabled, config.ProtoModeUDP),
			want: true,
		},
	}

	for _, c := range cases {
		if got := firewallNeedsRebuild(&c.old, &c.new); got != c.want {
			t.Errorf("%s: firewallNeedsRebuild = %v，期望 %v", c.name, got, c.want)
		}
	}
}

// withProto 返回把抓包协议设为 proto 的配置副本。
func withProto(cfg config.Config, proto string) config.Config {
	cfg.Capture.Protocol = proto
	return cfg
}

// withSnaplen 返回把 snaplen 设为 n 的配置副本。
func withSnaplen(cfg config.Config, n int) config.Config {
	cfg.Capture.Snaplen = n
	return cfg
}

// -c/--config 的四种写法都应被识别，且取最先出现者。
func TestExtractConfigFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{"short space", []string{"-c", "a.toml"}, "a.toml", true},
		{"long space", []string{"--config", "b.toml"}, "b.toml", true},
		{"long eq", []string{"--config=c.toml"}, "c.toml", true},
		{"short eq", []string{"-c=d.toml"}, "d.toml", true},
		{"single dash long", []string{"-config", "e.toml"}, "e.toml", true},
		{"absent", []string{"-i", "br-lan"}, "", false},
		{"missing value", []string{"-c"}, "", false},
		{"first wins", []string{"-c", "first.toml", "--config", "second.toml"}, "first.toml", true},
	}
	for _, c := range cases {
		got, ok := extractConfigFlag(c.args)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: extractConfigFlag(%v) = (%q,%v)，期望 (%q,%v)", c.name, c.args, got, ok, c.want, c.ok)
		}
	}
}
