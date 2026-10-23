package blocker

import (
	"pcdn-detect/internal/config"
	"pcdn-detect/internal/util"
)

// FullBanConfig 描述全 UDP 端口封禁模式。
type FullBanConfig struct {
	Enabled   bool                // 是否启用（mode != off，且防火墙已启用）
	Mode      string              // config.FullBanOn / config.FullBanDevice
	Threshold int                 // 触发阈值：被封禁的不同端口数达到该值
	Devices   map[string]struct{} // device 模式下启用全端口封禁的设备 MAC（小写）
}

// bumpPortLocked 调整某设备某端口的引用计数，并维护「被封禁的不同端口数」。
// 调用方须持有 b.mu。同一端口的 IPv4 / IPv6 各算一次引用，但只计为一个端口。
func (b *Blocker) bumpPortLocked(mac string, port uint16, delta int) {
	pm := b.devPorts[mac]
	if pm == nil {
		if delta <= 0 {
			return
		}
		pm = make(map[uint16]int)
		b.devPorts[mac] = pm
	}
	n := pm[port] + delta
	if n <= 0 {
		delete(pm, port)
		if b.devPortCount[mac] > 0 {
			b.devPortCount[mac]--
		}
		if len(pm) == 0 {
			delete(b.devPorts, mac)
			delete(b.devPortCount, mac)
		}
		return
	}
	if pm[port] == 0 {
		b.devPortCount[mac]++
	}
	pm[port] = n
}

// maybeFullBan 在设备被封禁端口数达到阈值时启用全 UDP 端口封禁，归零时解除。
// device 模式下仅对 FullBanConfig.Devices 中的设备生效。
func (b *Blocker) maybeFullBan(mac, ip string) {
	if !b.fb.Enabled || b.fw == nil || !b.fw.FullBanEnabled() {
		return
	}
	if b.fb.Mode == config.FullBanDevice {
		if _, ok := b.fb.Devices[mac]; !ok {
			return
		}
	}

	b.mu.Lock()
	count := b.devPortCount[mac]
	active := b.fullBanned[mac]
	var doBan, doUnban bool
	if !active && count >= b.fb.Threshold {
		b.fullBanned[mac] = true
		doBan = true
	} else if active && count == 0 {
		delete(b.fullBanned, mac)
		doUnban = true
	}
	b.mu.Unlock()

	switch {
	case doBan:
		b.applyFull(true, mac, ip)
	case doUnban:
		b.applyFull(false, mac, ip)
	}
}

// applyFull 执行 / 解除某设备的全 UDP 端口封禁。ip 供 hook 的 {ip} 占位符使用。
func (b *Blocker) applyFull(ban bool, mac, ip string) {
	if ban {
		if err := b.fw.FullBan(mac, ip); err != nil {
			b.logger.Printf("对设备 %s 执行全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			// 回滚标记，避免后续不再重试。
			b.mu.Lock()
			delete(b.fullBanned, mac)
			b.mu.Unlock()
			return
		}
		b.logger.Printf("设备 %s 被封禁端口数达到 %d，已执行全 UDP 端口封禁（仅放行端口：%s）",
			util.MaskDeviceMAC(b.hide.Load(), mac), b.fb.Threshold, portsLabel(b.fw.FullBanAllowPorts()))
		// 全 UDP 端口封禁已覆盖该设备的全部 UDP 端口，移除此前按端口单独下发的冗余 UDP 规则。
		b.removeRedundantPortRules(mac)
		return
	}
	if err := b.fw.FullUnban(mac, ip); err != nil {
		b.logger.Printf("解除设备 %s 的全 UDP 端口封禁失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
		return
	}
	b.logger.Printf("设备 %s 已无被封禁端口，已解除全 UDP 端口封禁", util.MaskDeviceMAC(b.hide.Load(), mac))
}

// removeRedundantPortRules 在全 UDP 端口封禁生效后，移除该设备此前按端口单独下发的冗余 UDP 封禁规则
// （这些端口已被设备级全封禁覆盖，无需再保留端口级规则）。
// 相关条目仍保留在 active / 端口统计中（其告警尚未结束），仅标记 applied=false，
// 使其告警结束 / 程序退出时不再重复解封。
// TCP 端口不在全 UDP 封禁的覆盖范围内，其端口级规则保留。
func (b *Blocker) removeRedundantPortRules(mac string) {
	type entry struct {
		ip    string
		port  uint16
		proto string
	}
	var entries []entry
	b.mu.Lock()
	for _, st := range b.active {
		if st.mac != mac || !st.applied || st.proto != protoUDP {
			continue
		}
		st.applied = false
		entries = append(entries, entry{st.ip, st.port, st.proto})
	}
	b.mu.Unlock()

	for _, e := range entries {
		b.apply(false, mac, e.ip, e.port, e.proto)
	}
}
