// Package config 负责加载与校验 TOML 配置，并定义各项配置的默认值与取值规范。
package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"pcdn-detect/internal/filter"
)

// DefaultConfig 返回使用内置默认值的配置。
func DefaultConfig() *Config {
	promisc := defaultPromisc
	return &Config{
		Detect: DetectConfig{
			Threshold:     defaultThreshold,
			Window:        Duration(defaultWindow),
			AlertDuration: Duration(defaultAlertDuration),
			Interval:      Duration(defaultInterval),
		},
		Capture: CaptureConfig{
			Promisc:   &promisc,
			FrameSize: defaultFrameSize,
			BlockSize: defaultBlockSize,
			NumBlocks: defaultNumBlocks,
			Snaplen:   defaultSnaplen,
			Protocol:  ProtoModeUDP,
		},
		Filter: FilterConfig{ListMode: filter.ModeWhitelist},
	}
}

// applyDefaults 为配置中缺失或非法的项填充内置默认值。
func (c *Config) applyDefaults() {
	if c.Detect.Threshold <= 0 {
		c.Detect.Threshold = defaultThreshold
	}
	if c.Detect.Window <= 0 {
		c.Detect.Window = Duration(defaultWindow)
	}
	if c.Detect.AlertDuration <= 0 {
		c.Detect.AlertDuration = Duration(defaultAlertDuration)
	}
	if c.Detect.Interval <= 0 {
		c.Detect.Interval = Duration(defaultInterval)
	}
	if c.Capture.Promisc == nil {
		promisc := defaultPromisc
		c.Capture.Promisc = &promisc
	}
	// 抓包缓冲非法或未配置时回退到内置默认值；protocol 未配置时默认 udp。
	// 注意：只更新缓冲相关字段，保留 Interface / Promisc。
	frame, block, blocks := c.Capture.RingParams()
	proto := c.Capture.CaptureProto()
	c.Capture.FrameSize, c.Capture.BlockSize, c.Capture.NumBlocks, c.Capture.Protocol = frame, block, blocks, proto
	c.Capture.Snaplen = c.Capture.SnaplenValue() // 未配置/非法时回落到默认 256，超过 frame_size 时截到 frame_size
	// 全端口封禁模式：未配置时默认 off；阈值非法时回退默认值。
	if c.FullBan.Mode == "" {
		c.FullBan.Mode = FullBanOff
	}
	if c.FullBan.Threshold <= 0 {
		c.FullBan.Threshold = defaultFullBanThreshold
	}
	// UPnP 拦截模式：未配置时默认 off。
	if c.UPnP.Mode == "" {
		c.UPnP.Mode = UPnPOff
	}
	// HTTP API 监听地址：未配置时默认回环地址（其余 HTTP 项由 HTTPConfig 方法兜底）。
	if strings.TrimSpace(c.HTTP.Listen) == "" {
		c.HTTP.Listen = defaultHTTPListen
	}
}

// parseConfig 解析 TOML 配置内容；未知键、类型错误等视为解析失败。
func parseConfig(data []byte) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, err
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, 0, len(un))
		for _, k := range un {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("未知配置项：%s", strings.Join(keys, ", "))
	}
	m, err := parseListMode(cfg.Filter.ListMode)
	if err != nil {
		return nil, err
	}
	cfg.Filter.ListMode = m
	proto, err := ParseCaptureProtocol(cfg.Capture.Protocol)
	if err != nil {
		return nil, err
	}
	cfg.Capture.Protocol = proto
	fb, err := ParseFullBanMode(cfg.FullBan.Mode)
	if err != nil {
		return nil, err
	}
	cfg.FullBan.Mode = fb
	up, err := ParseUPnPMode(cfg.UPnP.Mode)
	if err != nil {
		return nil, err
	}
	cfg.UPnP.Mode = up
	return &cfg, nil
}
