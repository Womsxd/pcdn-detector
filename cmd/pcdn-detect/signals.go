package main

import (
	"context"
	"os"

	"pcdn-detect/internal/httpapi"
	"pcdn-detect/internal/logx"
)

// handleSignals 处理热重载与退出信号：
//   - SIGHUP：重载配置（与 HTTP /reload 共用同一把锁，天然串行）；
//   - SIGINT / SIGTERM：取消 ctx，进入正常退出流程。
//
// 重载期间重复到达的 SIGHUP 会合并为一次：hupCh 容量为 1（内核丢弃多余信号），
// 且处理前后各清空一次缓冲，避免一次 reload 之后立刻又触发一次。
// 两类信号使用独立 channel，因此合并 SIGHUP 不会挤掉退出信号。
func handleSignals(hupCh, termCh <-chan os.Signal, reload httpapi.ReloadFunc, logger *logx.Logger, cancel context.CancelFunc) {
	for {
		select {
		case <-termCh:
			logger.Infof("收到退出信号，正在停止...")
			cancel()
			return
		case <-hupCh:
			drainSignals(hupCh)
			res, err := reload()
			if err != nil {
				logger.Warnf("SIGHUP 重载配置失败：%v", err)
			} else {
				logger.Infof("SIGHUP 已重载配置：%s", joinOrNone(res.Applied))
			}
			drainSignals(hupCh)
		}
	}
}

// drainSignals 非阻塞清空信号 channel（仅用于合并重复的 SIGHUP）。
func drainSignals(ch <-chan os.Signal) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
