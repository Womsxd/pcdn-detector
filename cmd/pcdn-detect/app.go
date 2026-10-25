package main

import (
	"context"
	"sync"
	"time"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/capture"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/httpapi"
	"pcdn-detect/internal/logx"
)

// app 持有进程级运行状态。reload 会原地替换防火墙 / 封禁协调器 / 抓包 / HTTP 服务，
// 这些可变字段统一收拢于此，由 mu 保护，避免散落成 main 里的闭包变量。
type app struct {
	logger *logx.Logger
	det    *detector.Detector

	ctx    context.Context
	cancel context.CancelFunc

	explicitConfig    string
	hasExplicitConfig bool
	ov                cliOverrides

	// mu 串行化 reload，并保护以下运行期可变字段：退出清理必须等仍在执行的 reload 结束，
	// 否则可能重复 Close 同一个 Blocker。
	mu               sync.Mutex
	cfg              *config.Config
	fw               *firewall.Firewall
	blk              *blocker.Blocker
	capturer         *capture.Capturer
	api              *httpapi.Server
	apiCancel        context.CancelFunc
	peerLimit        int
	gcPercent        int
	memLimit         int64
	restartRequested bool

	// 扫描间隔可被 reload 动态调整；用独立锁避免与 mu 相互等待。
	intervalMu   sync.Mutex
	scanInterval time.Duration
}

// startHTTP 按配置启动 HTTP 服务（独立子 ctx，便于 reload 时原地重启监听）。
func (a *app) startHTTP(hc config.HTTPConfig) error {
	srv, err := httpapi.New(a.det, a.blk, hc, a.reload, a.logger)
	if err != nil {
		return err
	}
	srv.SetRuntimeLimits(a.gcPercent, a.memLimit)
	hcCtx, hcCancel := context.WithCancel(a.ctx)
	a.api, a.apiCancel = srv, hcCancel
	go func() {
		if rerr := srv.Run(hcCtx); rerr != nil {
			a.logger.Errorf("HTTP API 已停止：%v", rerr)
		}
	}()
	authInfo := "无鉴权"
	switch {
	case hc.BearerToken() != "":
		authInfo = "Bearer 鉴权"
	case hc.NoToken():
		authInfo = "无鉴权（token = " + config.TokenAllowNoToken + "）"
	}
	a.logger.Infof("HTTP API 已启用：http://%s（%s；/peers 每端口对端 IP 上限 %d）",
		hc.ListenAddr(), authInfo, hc.DeviceIPLimitValue())
	return nil
}

// stopHTTP 停止当前 HTTP 服务（若未运行则为空操作）。
func (a *app) stopHTTP() {
	if a.apiCancel != nil {
		a.apiCancel()
		a.apiCancel = nil
	}
	a.api = nil
}

// setInterval 更新扫描间隔；非正值忽略。
func (a *app) setInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	a.intervalMu.Lock()
	a.scanInterval = d
	a.intervalMu.Unlock()
}

// getInterval 返回当前扫描间隔。
func (a *app) getInterval() time.Duration {
	a.intervalMu.Lock()
	defer a.intervalMu.Unlock()
	return a.scanInterval
}

// cleanupFirewall 兜底解封并清理本程序添加的防火墙规则；正常退出与启动失败路径共用。
// 启动失败时 logger.Fatalf 会直接 os.Exit，defer 不会执行，故这些路径必须显式调用。
func (a *app) cleanupFirewall() {
	if a.blk != nil {
		a.blk.Close()
	}
	if a.fw != nil {
		a.fw.Cleanup()
	}
}
