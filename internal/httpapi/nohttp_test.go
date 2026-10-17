//go:build nohttp

package httpapi

import (
	"context"
	"errors"
	"log"
	"testing"

	"pcdn-detect/internal/config"
)

// nohttp 构建下：New / Run 必须返回 ErrDisabled，且不 panic。
func TestNoHTTPBuild(t *testing.T) {
	srv, err := New(nil, nil, config.HTTPConfig{Enabled: true, Listen: "127.0.0.1:8080"}, nil, log.Default())
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("应返回 ErrDisabled，got %v", err)
	}
	if srv != nil {
		t.Fatalf("nohttp 构建不应返回可用 Server")
	}

	// 方法级兜底：即便有人持有零值 Server，也不能 panic。
	var zero Server
	if err := zero.Run(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Run 应返回 ErrDisabled，got %v", err)
	}
	zero.SetToken("x")
	zero.SetDeviceIPLimit(10)
}
