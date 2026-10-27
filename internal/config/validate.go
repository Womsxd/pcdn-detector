package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"pcdn-detect/internal/filter"
	"pcdn-detect/internal/logx"
)

// Validate 校验配置的语义合法性：只做纯计算，不访问网络、文件系统，也不执行外部命令。
// 供启动、reload 预检与 --test-config 共用：校验通过之前不改变任何运行状态，
// 避免「重载到一半才发现配置非法」而回退重启。
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Capture.Interface) == "" {
		return fmt.Errorf("[capture] interface 未配置：请填写网卡名（如 br-lan），或使用 -i/--interface 指定")
	}
	if c.Detect.Threshold <= 0 {
		return fmt.Errorf("[detect] threshold 必须大于 0，得到 %d", c.Detect.Threshold)
	}
	if c.Detect.Window <= 0 {
		return fmt.Errorf("[detect] window 必须大于 0，得到 %s", c.Detect.Window)
	}
	if c.Detect.AlertDuration <= 0 {
		return fmt.Errorf("[detect] alert_duration 必须大于 0，得到 %s", c.Detect.AlertDuration)
	}
	if c.Detect.Interval <= 0 {
		return fmt.Errorf("[detect] interval 必须大于 0，得到 %s", c.Detect.Interval)
	}

	// 日志等级：留空由 applyDefaults 补默认值，显式配置时必须是合法取值。
	if strings.TrimSpace(c.Log.Level) != "" {
		if _, err := logx.ParseLevel(c.Log.Level); err != nil {
			return fmt.Errorf("[log] %w", err)
		}
	}

	if c.Memory.Limit != "" {
		if _, err := ParseByteSize(c.Memory.Limit); err != nil {
			return fmt.Errorf("[memory] memory_limit 无效：%w", err)
		}
	}
	if _, err := c.GCPercentValue(); err != nil {
		return fmt.Errorf("[memory] %w", err)
	}

	switch c.Filter.ListMode {
	case filter.ModeBlacklist, filter.ModeWhitelist:
	default:
		return fmt.Errorf("[filter] list_mode 无效：%q（可选 blacklist / whitelist）", c.Filter.ListMode)
	}
	blacklist, whitelist, err := c.ListEntries()
	if err != nil {
		return fmt.Errorf("[filter] %w", err)
	}
	flt, err := filter.NewDeviceFilter(c.Filter.ListMode, blacklist, whitelist)
	if err != nil {
		return fmt.Errorf("[filter] %w", err)
	}
	if flt.Empty() {
		return fmt.Errorf("[filter] list_mode = \"blacklist\" 但未配置 blacklist，将不会检测任何设备")
	}

	// 放行端口的表达式在功能关闭时也校验：语法错误在任何模式下都是配置错误。
	if _, err := c.FullBanAllow(); err != nil {
		return err
	}
	if c.FullBan.FullBanEnabled() {
		if _, err := c.FullBanDevices(); err != nil {
			return fmt.Errorf("[full_ban] %w", err)
		}
	}
	if _, err := c.UPnPPorts(); err != nil {
		return err
	}
	if c.UPnP.UPnPEnabled() {
		if _, err := c.UPnPFilterValue(); err != nil {
			return fmt.Errorf("[upnp] %w", err)
		}
	}

	return c.HTTP.Validate()
}

// Validate 校验 [http] 配置：监听地址格式、端口合法性，以及非回环监听必须鉴权。
// 与 New 的启动检查一致，便于 reload / --test-config 提前发现无法启动的监听配置。
func (c HTTPConfig) Validate() error {
	for _, origin := range c.CORSAllowedOrigins {
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
	}
	if c.CORSAllowCredentials && c.CORSAnyOrigin() {
		return fmt.Errorf("[http] cors_allow_credentials = true 时不能使用通配来源 \"*\"，请显式列出允许的来源")
	}
	if c.CORSMaxAge != nil && *c.CORSMaxAge < 0 {
		return fmt.Errorf("[http] cors_max_age 不能为负数：%d", *c.CORSMaxAge)
	}
	if !c.Enabled {
		return nil
	}
	listen := c.ListenAddr()
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("[http] listen 无效（应为 host:port）：%s", listen)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("[http] listen 端口无效：%s", listen)
	}
	if !IsLoopbackHost(host) && c.BearerToken() == "" && !c.NoToken() {
		return fmt.Errorf("[http] listen 绑定到非回环地址 %s 时必须配置 http.token（如确需无鉴权，可设 token = %q）", listen, TokenAllowNoToken)
	}
	return nil
}

// validateCORSOrigin 校验一个 CORS 允许来源：通配 "*"，或形如 scheme://host[:port] 的 origin。
// origin 不含路径 / 查询 / 片段，也不允许携带用户信息；末尾 "/" 会被忽略。
func validateCORSOrigin(origin string) error {
	o := strings.TrimSpace(origin)
	if o == "" {
		return fmt.Errorf("[http] cors_allowed_origins 不能包含空来源")
	}
	if o == "*" {
		return nil
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return fmt.Errorf("[http] cors_allowed_origins 中的来源无效（应为 scheme://host[:port]，或 \"*\"）：%q", origin)
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return fmt.Errorf("[http] cors_allowed_origins 中的来源仅支持 http / https：%q", origin)
	}
	if strings.Contains(u.Host, "*") {
		return fmt.Errorf("[http] cors_allowed_origins 不支持通配子域（需要允许任意来源时用 \"*\"）：%q", origin)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("[http] cors_allowed_origins 中的来源不能带路径：%q", origin)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("[http] cors_allowed_origins 中的来源不能带查询 / 片段 / 用户信息：%q", origin)
	}
	return nil
}

// IsLoopbackHost 判断监听主机名是否为回环（localhost / 127.0.0.0/8 / ::1）。
// 空主机名（如 ":8080"，表示监听全部地址）视为非回环。
func IsLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if h == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.IsLoopback()
	}
	return false
}
