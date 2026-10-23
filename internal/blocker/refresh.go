package blocker

import "time"

// refreshLoop 周期刷新 nftables 封禁元素的内核超时：配置了 ban_ttl 时按 TTL/3 续期，
// 使进程被 SIGKILL / OOM 杀死后规则仍能在 TTL 内自动过期；未配置时每分钟检查一次
// （支持 reload 后新配置生效）。
func (b *Blocker) refreshLoop() {
	defer b.wg.Done()
	for {
		ttl := b.currentBanTTL()
		wait := time.Minute
		if ttl > 0 {
			wait = ttl / 3
			if wait < time.Second {
				wait = time.Second
			}
		}
		select {
		case <-b.done:
			return
		case <-time.After(wait):
		}
		if ttl > 0 {
			b.refreshBans()
		}
	}
}

// currentBanTTL 返回当前防火墙的封禁元素超时（与 Migrate 互斥读取，0 表示未启用）。
func (b *Blocker) currentBanTTL() time.Duration {
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()
	if b.fw == nil {
		return 0
	}
	return b.fw.BanTTL()
}

// refreshBans 重新下发当前仍生效的封禁条目，以刷新 nftables 元素超时。
// 只在 ban_ttl 启用时才有实际动作；失败只汇总告警，避免刷屏。
func (b *Blocker) refreshBans() {
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()
	if b.fw == nil || b.fw.BanTTL() <= 0 {
		return
	}

	type entry struct {
		mac   string
		ip    string
		port  uint16
		proto string
	}
	b.mu.Lock()
	bans := make([]entry, 0, len(b.active))
	for _, st := range b.active {
		if st.applied {
			bans = append(bans, entry{st.mac, st.ip, st.port, st.proto})
		}
	}
	full := make([]entry, 0, len(b.fullBanned))
	for mac := range b.fullBanned {
		full = append(full, entry{mac: mac, ip: b.devIP[mac]})
	}
	b.mu.Unlock()

	failed := 0
	for _, e := range bans {
		if err := b.fw.Ban(e.mac, e.ip, e.port, e.proto); err != nil {
			failed++
		}
	}
	for _, e := range full {
		if err := b.fw.FullBan(e.mac, e.ip); err != nil {
			failed++
		}
	}
	if failed > 0 {
		b.logger.Warnf("警告：刷新 %d 条封禁元素的超时失败（可能因刷新失败而提前失效）", failed)
	}
}
