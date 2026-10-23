package blocker

import (
	"net/netip"
	"strings"

	"pcdn-detect/internal/firewall"
	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/state"
	"pcdn-detect/internal/util"
)

// BlockState 导出当前封禁状态（供 reload 重启继承）。
func (b *Blocker) BlockState() state.BlockState {
	b.mu.Lock()
	defer b.mu.Unlock()

	var s state.BlockState
	for _, st := range b.active {
		mac, err := netutil.ParseMAC(st.mac)
		if err != nil {
			continue
		}
		s.Bans = append(s.Bans, state.BanEntry{
			MAC: mac, Port: st.port, Proto: protoToU8(st.proto),
			Family: familyToU8(st.family), IP: parseAddr(st.ip), Refs: st.refs, Applied: st.applied,
		})
	}
	for mac, on := range b.fullBanned {
		if !on {
			continue
		}
		m, err := netutil.ParseMAC(mac)
		if err != nil {
			continue
		}
		s.FullBanned = append(s.FullBanned, state.FullBanEntry{MAC: m, IP: parseAddr(b.devIP[mac])})
	}
	s.UPnPBlocked = macsOf(b.upnpBlocked)
	s.UPnPAllowed = macsOf(b.upnpAllowed)
	s.UPnPAll = b.upnpAll
	return s
}

// Restore 按状态还原并重新下发封禁（启动继承时调用，使用当前防火墙后端）。
// 与构造期的 applyStaticUPnP 幂等协作：已存在的条目 / 状态不会重复下发。
func (b *Blocker) Restore(s state.BlockState) {
	if b.fw == nil {
		return
	}
	for _, e := range s.Bans {
		mac := e.MAC.String()
		proto := u8ToProto(e.Proto)
		ip := addrToString(e.IP)
		key := b.key(mac, e.Port, proto, ip)
		b.mu.Lock()
		if _, ok := b.active[key]; ok {
			b.mu.Unlock()
			continue
		}
		refs := e.Refs
		if refs < 1 {
			refs = 1
		}
		b.active[key] = &banState{mac: mac, port: e.Port, proto: proto, family: u8ToFamily(e.Family), ip: ip, refs: refs, applied: e.Applied}
		b.bumpPortLocked(mac, e.Port, 1)
		b.mu.Unlock()

		if e.Applied {
			if err := b.fw.Ban(mac, ip, e.Port, proto); err != nil {
				b.logger.Errorf("继承封禁设备 %s 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), strings.ToUpper(proto), e.Port, err)
			}
		}
	}
	for _, e := range s.FullBanned {
		mac := e.MAC.String()
		b.mu.Lock()
		if b.fullBanned[mac] {
			b.mu.Unlock()
			continue
		}
		b.fullBanned[mac] = true
		b.mu.Unlock()
		if err := b.fw.FullBan(mac, addrToString(e.IP)); err != nil {
			b.logger.Errorf("继承全 UDP 端口封禁设备 %s 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), err)
			b.mu.Lock()
			delete(b.fullBanned, mac)
			b.mu.Unlock()
		}
	}
	for _, m := range s.UPnPBlocked {
		b.applyUPnPBan(true, m.String())
	}
	for _, m := range s.UPnPAllowed {
		b.applyUPnPAllow(true, m.String())
	}
	if s.UPnPAll {
		b.mu.Lock()
		already := b.upnpAll
		b.mu.Unlock()
		if !already {
			if err := b.fw.UPnPBlockAll(); err != nil {
				b.logger.Errorf("继承 UPnP 全量拦截失败：%v", err)
			} else {
				b.mu.Lock()
				b.upnpAll = true
				b.mu.Unlock()
			}
		}
	}
}

// Migrate 在暂停事件处理的前提下把防火墙原地迁移到新配置，返回新后端对象：
//   - 先按旧后端逐条解封并清理旧规则（break），再调用 build 建新后端并重新下发（make）；
//   - Blocker 对象本身不变，因此检测层 sink 与 HTTP 持有的指针始终有效；迁移期间到达的
//     告警事件会排在队列里，迁移完成后按新后端处理，不会被投递给已销毁的对象；
//   - 迁移失败时内存状态保持不变并原样返回错误（调用方通常回退到重启，按状态文件恢复）。
//
// 调用方须保证 build 返回的配置（fb / up）与 nfw 一致。
func (b *Blocker) Migrate(build func() (*firewall.Firewall, FullBanConfig, UPnPConfig, error)) (*firewall.Firewall, error) {
	b.migrateMu.Lock()
	defer b.migrateMu.Unlock()

	snap := b.BlockState()

	// 1) 解除旧后端规则并清理其残留（nftables 需整表删除，hook / iptables 主要靠逐条解封）。
	if b.fw != nil {
		b.unbanAllRules()
		b.fw.Cleanup()
	}

	// 2) 建新后端。失败时保留原 fw 与状态，由调用方决定回退方式。
	nfw, fb, up, err := build()
	if err != nil {
		return nil, err
	}
	b.fw, b.fb, b.up = nfw, fb, up

	// 3) 清空内存状态后按快照重建：Restore 会跳过已存在的条目，故必须先清空；
	//    UPnP 的静态配置（名单 / 全量拦截）不在快照里，需按新配置重新应用。
	b.mu.Lock()
	b.resetStateLocked()
	b.mu.Unlock()
	b.applyStaticUPnP()
	b.Restore(snap)
	return nfw, nil
}

// AdoptSessions 把检测层当前仍处于告警中的端口补发为封禁（[firewall] ban_active_alerts）。
// 用于启用防火墙时不再等下一轮告警：已存在的条目由 Restore 跳过，因此可安全重复调用。
// 同一封禁键的多个会话（ban_both 时 v4/v6）会合并引用计数，避免一端结束就提前解封。
func (b *Blocker) AdoptSessions(sessions []state.AlertSession) {
	if len(sessions) == 0 {
		return
	}
	// 取写锁：与事件处理 / Migrate 互斥，保证补发期间不会与解封、换后端交错。
	b.migrateMu.Lock()
	defer b.migrateMu.Unlock()
	if b.fw == nil {
		return
	}

	type agg struct {
		entry state.BanEntry
		ip    string
		refs  int
	}
	byKey := make(map[string]*agg, len(sessions))
	order := make([]string, 0, len(sessions))
	for _, s := range sessions {
		mac := s.MAC.String()
		ip := addrToString(s.IP)
		key := b.key(mac, s.Port, u8ToProto(s.Proto), ip)
		if a := byKey[key]; a != nil {
			a.refs++
			continue
		}
		family := state.FamilyV4
		if s.V6 {
			family = state.FamilyV6
		}
		byKey[key] = &agg{
			entry: state.BanEntry{MAC: s.MAC, Port: s.Port, Proto: s.Proto, Family: family, IP: s.IP, Applied: true},
			ip:    ip,
			refs:  1,
		}
		order = append(order, key)
	}

	var st state.BlockState
	for _, k := range order {
		a := byKey[k]
		e := a.entry
		e.Refs = a.refs
		st.Bans = append(st.Bans, e)
	}
	b.Restore(st)

	// Restore 不触发全端口封禁判定：补发后按设备重新评估一次。
	seen := make(map[string]struct{}, len(order))
	for _, k := range order {
		a := byKey[k]
		mac := a.entry.MAC.String()
		if _, ok := seen[mac]; ok {
			continue
		}
		seen[mac] = struct{}{}
		b.maybeFullBan(mac, a.ip)
	}
}

func protoToU8(proto string) uint8 {
	if proto == "tcp" {
		return netutil.ProtoTCP
	}
	return netutil.ProtoUDP
}

func u8ToProto(p uint8) string {
	if p == netutil.ProtoTCP {
		return "tcp"
	}
	return protoUDP
}

func familyToU8(f string) uint8 {
	switch f {
	case "v4":
		return state.FamilyV4
	case "v6":
		return state.FamilyV6
	default:
		return state.FamilyNone
	}
}

func u8ToFamily(f uint8) string {
	switch f {
	case state.FamilyV4:
		return "v4"
	case state.FamilyV6:
		return "v6"
	default:
		return ""
	}
}

func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

func addrToString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.Unmap().String()
}

func macsOf(m map[string]bool) []netutil.MAC {
	var out []netutil.MAC
	for s, on := range m {
		if !on {
			continue
		}
		if mac, err := netutil.ParseMAC(s); err == nil {
			out = append(out, mac)
		}
	}
	return out
}
