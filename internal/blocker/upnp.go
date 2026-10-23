package blocker

import "pcdn-detect/internal/util"

// UPnPConfig 描述 UPnP 拦截模式。
type UPnPConfig struct {
	Enabled  bool     // 是否启用（mode != off，且防火墙已启用）
	Mode     string   // config.UPnPOn / config.UPnPDevice
	BlockAll bool     // true：拦截全部进入路由器的 UPnP（白名单模式），Targets 为放行名单；false：仅拦截 Targets
	Targets  []string // 关联设备 MAC（BlockAll 时为放行名单，否则为拦截名单）
}

// applyStaticUPnP 在启动时立即应用 UPnP 拦截：
//   - 黑名单模式（BlockAll=false）：逐个拦截 up.Targets 中的设备；
//   - 白名单模式（BlockAll=true）：先拦截全部进入路由器的 UPnP，再为 up.Targets 中的设备放行。
func (b *Blocker) applyStaticUPnP() {
	if !b.up.Enabled || b.fw == nil || !b.fw.UPnPEnabled() {
		return
	}
	if b.up.BlockAll {
		if err := b.fw.UPnPBlockAll(); err != nil {
			b.logger.Printf("拦截全部 UPnP 请求失败：%v", err)
		} else {
			b.mu.Lock()
			b.upnpAll = true
			b.mu.Unlock()
			b.logger.Printf("已拦截全部进入路由器的 UPnP 请求（目的端口：%s）", portsLabel(b.fw.UPnPPorts()))
		}
		for _, mac := range b.up.Targets {
			b.applyUPnPAllow(true, mac)
		}
		return
	}
	for _, mac := range b.up.Targets {
		b.applyUPnPBan(true, mac)
	}
}

// applyUPnPBan 执行 / 解除某设备的 UPnP 拦截（黑名单模式）。返回是否发生了实际的状态变化。
func (b *Blocker) applyUPnPBan(ban bool, mac string) bool {
	if !b.up.Enabled || b.fw == nil || !b.fw.UPnPEnabled() {
		return false
	}
	b.mu.Lock()
	already := b.upnpBlocked[mac]
	b.mu.Unlock()
	if ban == already {
		return false
	}

	if ban {
		if err := b.fw.UPnPBan(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("拦截设备 %s 的 UPnP 请求失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			return false
		}
		b.mu.Lock()
		b.upnpBlocked[mac] = true
		b.mu.Unlock()
		b.logger.Printf("已拦截设备 %s 的 UPnP 请求（目的端口：%s）",
			util.MaskDeviceMAC(b.hide.Load(), mac), portsLabel(b.fw.UPnPPorts()))
		return true
	}

	if err := b.fw.UPnPUnban(mac, b.devIPOf(mac)); err != nil {
		b.logger.Printf("解除设备 %s 的 UPnP 拦截失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
		return false
	}
	b.mu.Lock()
	delete(b.upnpBlocked, mac)
	b.mu.Unlock()
	b.logger.Printf("已解除设备 %s 的 UPnP 拦截", util.MaskDeviceMAC(b.hide.Load(), mac))
	return true
}

// applyUPnPAllow 执行 / 解除某设备的 UPnP 放行（白名单模式）。返回是否发生了实际的状态变化。
func (b *Blocker) applyUPnPAllow(allow bool, mac string) bool {
	if !b.up.Enabled || b.fw == nil || !b.fw.UPnPEnabled() {
		return false
	}
	b.mu.Lock()
	already := b.upnpAllowed[mac]
	b.mu.Unlock()
	if allow == already {
		return false
	}

	if allow {
		if err := b.fw.UPnPAllow(mac, b.devIPOf(mac)); err != nil {
			b.logger.Printf("放行设备 %s 的 UPnP 请求失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			return false
		}
		b.mu.Lock()
		b.upnpAllowed[mac] = true
		b.mu.Unlock()
		b.logger.Printf("已放行设备 %s 的 UPnP 请求（目的端口：%s）",
			util.MaskDeviceMAC(b.hide.Load(), mac), portsLabel(b.fw.UPnPPorts()))
		return true
	}

	if err := b.fw.UPnPDisallow(mac, b.devIPOf(mac)); err != nil {
		b.logger.Printf("取消设备 %s 的 UPnP 放行失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
		return false
	}
	b.mu.Lock()
	delete(b.upnpAllowed, mac)
	b.mu.Unlock()
	b.logger.Printf("已取消设备 %s 的 UPnP 放行", util.MaskDeviceMAC(b.hide.Load(), mac))
	return true
}
