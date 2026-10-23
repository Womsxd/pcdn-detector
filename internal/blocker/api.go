package blocker

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/util"
)

// Snapshot 是封禁状态的只读快照（供 HTTP API 使用）。
type Snapshot struct {
	Bans        []BanView `json:"bans"`
	FullBanned  []string  `json:"full_banned"`
	UPnPBlocked []string  `json:"upnp_blocked"`
	UPnPAllowed []string  `json:"upnp_allowed"`
	UPnPAll     bool      `json:"upnp_all"`
}

// BanView 是一条端口级封禁条目的快照。
type BanView struct {
	MAC     string `json:"mac"`
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	Family  string `json:"family,omitempty"`
	Refs    int    `json:"refs"`
	IP      string `json:"ip,omitempty"`
	Applied bool   `json:"applied"`
}

// Snapshot 返回当前封禁状态（端口级封禁 / 全端口封禁 / UPnP 拦截放行）。
func (b *Blocker) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := Snapshot{UPnPAll: b.upnpAll}
	for _, st := range b.active {
		out.Bans = append(out.Bans, BanView{
			MAC: st.mac, Port: st.port, Proto: st.proto, Family: st.family,
			Refs: st.refs, IP: st.ip, Applied: st.applied,
		})
	}
	sort.Slice(out.Bans, func(i, j int) bool {
		if out.Bans[i].MAC != out.Bans[j].MAC {
			return out.Bans[i].MAC < out.Bans[j].MAC
		}
		if out.Bans[i].Port != out.Bans[j].Port {
			return out.Bans[i].Port < out.Bans[j].Port
		}
		return out.Bans[i].Proto < out.Bans[j].Proto
	})
	for mac, on := range b.fullBanned {
		if on {
			out.FullBanned = append(out.FullBanned, mac)
		}
	}
	for mac, on := range b.upnpBlocked {
		if on {
			out.UPnPBlocked = append(out.UPnPBlocked, mac)
		}
	}
	for mac, on := range b.upnpAllowed {
		if on {
			out.UPnPAllowed = append(out.UPnPAllowed, mac)
		}
	}
	sort.Strings(out.FullBanned)
	sort.Strings(out.UPnPBlocked)
	sort.Strings(out.UPnPAllowed)
	return out
}

// ForceUnban 手动解封某 MAC 在指定协议下的端口，返回移除的封禁条目数。
// 仅对已下发端口级规则的条目调用防火墙解封（被全端口封禁覆盖的条目无需单独解封）。
func (b *Blocker) ForceUnban(mac string, port uint16, proto string) (int, error) {
	// 与 Migrate 互斥：避免迁移中途对旧 / 新后端各下发一半解封命令。
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()

	if b.fw == nil {
		return 0, errors.New("防火墙未启用")
	}
	macAddr, err := netutil.ParseMAC(mac)
	if err != nil {
		return 0, fmt.Errorf("MAC 无效：%q", mac)
	}
	mac = macAddr.String()
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != protoUDP && proto != "tcp" {
		return 0, fmt.Errorf("proto 无效：%q（可选 udp / tcp）", proto)
	}

	type target struct {
		ip    string
		proto string
	}
	var targets []target
	removed := 0
	b.mu.Lock()
	for key, st := range b.active {
		if st.mac != mac || st.port != port || st.proto != proto {
			continue
		}
		if st.applied {
			targets = append(targets, target{st.ip, st.proto})
		}
		delete(b.active, key)
		b.bumpPortLocked(mac, port, -1)
		removed++
	}
	b.mu.Unlock()

	var firstErr error
	for _, t := range targets {
		label := strings.ToUpper(t.proto)
		if err := b.fw.Unban(mac, t.ip, port, t.proto); err != nil {
			b.logger.Errorf("手动解封设备 %s 的 %s 端口 %d 失败：%v", util.MaskDeviceMAC(b.hide.Load(), mac), label, port, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		b.logger.Infof("已手动解封设备 %s 的 %s 端口 %d", util.MaskDeviceMAC(b.hide.Load(), mac), label, port)
	}
	return removed, firstErr
}
