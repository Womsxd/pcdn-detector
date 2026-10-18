package main

import (
	"io"
	"log"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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
