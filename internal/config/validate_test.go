package config

import (
	"os"
	"strings"
	"testing"

	"pcdn-detect/internal/filter"
)

// validConfig 返回一份可通过校验的基线配置（默认值 + 必填网卡）。
func validConfig() *Config {
	c := DefaultConfig()
	c.Capture.Interface = "br-lan"
	return c
}

// Validate 应接受合法配置，并对每类语义错误给出明确提示。
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"默认配置", func(*Config) {}, ""},
		{"缺少网卡", func(c *Config) { c.Capture.Interface = " " }, "[capture] interface"},
		{"黑名单 MAC 非法", func(c *Config) {
			c.Filter.ListMode = filter.ModeBlacklist
			c.Filter.Blacklist = []listEntry{{MAC: "not-a-mac"}}
		}, "[filter]"},
		{"黑名单为空", func(c *Config) { c.Filter.ListMode = filter.ModeBlacklist }, "未配置 blacklist"},
		{"名单模式非法", func(c *Config) { c.Filter.ListMode = "none" }, "list_mode 无效"},
		{"memory_limit 非法", func(c *Config) { c.Memory.Limit = "12XB" }, "memory_limit"},
		{"gc_percent 越界", func(c *Config) {
			p := 0
			c.Memory.GCPercent = &p
		}, "gc_percent"},
		{"full_ban allow 端口非法", func(c *Config) { c.FullBan.Allow = []any{"70000"} }, "[full_ban] allow"},
		{"upnp 端口非法", func(c *Config) { c.UPnP.Ports = []any{-1} }, "[upnp] ports"},
		{"upnp 设备 MAC 非法", func(c *Config) {
			c.UPnP.Mode = UPnPDevice
			c.Filter.Whitelist = []listEntry{{MAC: "bad", UPnP: boolPtr(true)}}
		}, "[filter]"},
		{"http listen 非法", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Listen = "127.0.0.1"
		}, "[http] listen"},
		{"http 非回环无鉴权", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Listen = "0.0.0.0:8080"
		}, "http.token"},
		{"http 非回环带鉴权", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Listen = "0.0.0.0:8080"
			c.HTTP.Token = "secret"
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错，got：%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("应报错且包含 %q，got：%v", tc.wantErr, err)
			}
		})
	}
}

// LoadConfigStrict 只读取已有配置文件：没有文件时报错且不创建任何文件。
func TestLoadConfigStrict(t *testing.T) {
	chdirTemp(t)
	if _, err := LoadConfigStrict("", false); err == nil {
		t.Fatal("没有配置文件时应报错")
	}
	for _, name := range configCreateNames {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("只校验时不应创建配置文件：%s", name)
		}
	}

	if err := os.WriteFile(configCandidates[0], []byte(defaultConfigTemplate), 0o644); err != nil {
		t.Fatalf("写入配置文件失败：%v", err)
	}
	res, err := LoadConfigStrict("", false)
	if err != nil {
		t.Fatalf("应能加载已有配置：%v", err)
	}
	if res.Path != configCandidates[0] || res.Created {
		t.Fatalf("加载结果不符：path=%s created=%v", res.Path, res.Created)
	}
}

func boolPtr(v bool) *bool { return &v }
