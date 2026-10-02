package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		iface    string
		trigger  int
		duration time.Duration
		promisc  bool
		interval time.Duration
	)

	flag.StringVar(&iface, "i", "", "要监听的网卡名称（必填），例如 br-lan、br0、eth0")
	flag.IntVar(&trigger, "c", 20, "触发次数：同一设备同一端口在时长内出现的不同远端公网IP数量达到该值即判定疑似PCDN")
	flag.DurationVar(&duration, "t", 60*time.Second, "检测时长（滑动窗口），支持 30s、5m、1h 等写法")
	flag.BoolVar(&promisc, "promisc", true, "是否开启混杂模式")
	flag.DurationVar(&interval, "interval", 2*time.Second, "检测扫描间隔")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PCDN 行为检测工具（运行于 OpenWrt / Linux 路由器）\n\n")
		fmt.Fprintf(os.Stderr, "用法: %s -i <网卡> [-c 触发次数] [-t 时长] [-interval 扫描间隔]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "示例: %s -i br-lan -c 20 -t 60s\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if iface == "" {
		fmt.Fprintln(os.Stderr, "错误：必须使用 -i 指定网卡，例如 -i br-lan")
		flag.Usage()
		os.Exit(2)
	}
	if trigger <= 0 {
		fmt.Fprintln(os.Stderr, "错误：-c 触发次数必须大于 0")
		os.Exit(2)
	}
	if duration <= 0 {
		fmt.Fprintln(os.Stderr, "错误：-t 时长必须大于 0")
		os.Exit(2)
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	det := NewDetector(trigger, duration, logger)

	cap, err := NewCapturer(iface, promisc, det)
	if err != nil {
		logger.Fatalf("初始化抓包失败（网卡 %s）：%v（请确认已以 root 运行且网卡存在）", iface, err)
	}
	defer cap.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Println("收到退出信号，正在停止...")
		cancel()
	}()

	// 定期扫描滑动窗口并产生告警。
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				det.Scan(now)
			}
		}
	}()

	logger.Printf("开始监听网卡 %s：触发阈值=%d，时长=%s，扫描间隔=%s",
		iface, trigger, duration, interval)

	if err := cap.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatalf("抓包异常退出：%v", err)
	}

	det.Scan(time.Now())
	det.Summary()
	logger.Println("已退出")
}
