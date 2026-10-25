//go:build nohttp

// Package httpapi 在 `-tags nohttp` 构建下只保留空壳：
// 不编译 HTTP 传输层（internal/minihttp）、路由、JSON 序列化等代码，
// 生成的二进制不含任何监听能力，体积更小。
//
// 该构建下 [http] enabled 必须为 false，否则启动会直接报错退出。
package httpapi

import (
	"context"
	"errors"

	"pcdn-detect/internal/blocker"
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
	"pcdn-detect/internal/logx"
)

// ErrDisabled 表示该二进制在编译期排除了 HTTP 功能。
var ErrDisabled = errors.New("此二进制在编译时排除了 HTTP 功能（-tags nohttp）：请将 [http] enabled 设为 false，或改用带 HTTP 的构建")

// ReloadResult 与启用 HTTP 时保持同一类型形态（reload 编排代码共用）。
type ReloadResult struct {
	Applied         []string `json:"applied"`
	RestartRequired []string `json:"restart_required"`
	Restarting      bool     `json:"restarting"`
}

// ReloadFunc 与启用 HTTP 时保持同一签名。
type ReloadFunc func() (ReloadResult, error)

// Server 是无 HTTP 构建下的占位类型。
type Server struct{}

// New 始终返回 [ErrDisabled]。
func New(_ *detector.Detector, _ *blocker.Blocker, _ config.HTTPConfig, _ ReloadFunc, _ *logx.Logger) (*Server, error) {
	return nil, ErrDisabled
}

// Run 始终返回 [ErrDisabled]。
func (s *Server) Run(context.Context) error { return ErrDisabled }

// SetToken 在无 HTTP 构建下为空操作。
func (s *Server) SetToken(string) {}

// SetDeviceIPLimit 在无 HTTP 构建下为空操作。
func (s *Server) SetDeviceIPLimit(int) {}

// SetCORS 在无 HTTP 构建下为空操作。
func (s *Server) SetCORS(_ []string, _ bool, _ int) {}

// SetRuntimeLimits 在无 HTTP 构建下为空操作。
func (s *Server) SetRuntimeLimits(int, int64) {}

// SetBlocker 在无 HTTP 构建下为空操作。
func (s *Server) SetBlocker(*blocker.Blocker) {}
