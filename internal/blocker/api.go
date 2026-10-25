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

const (
	familyV4 = "v4"
	familyV6 = "v6"
)

// Counts 是封禁状态的计数汇总，供 /status 之类的接口使用。
// 与 Snapshot 各切片的 len 口径一致，但只在锁内读取计数，不复制条目、不排序、不构造 MAC 字符串。
type Counts struct {
	ActiveBans  int
	FullBanned  int
	UPnPBlocked int
	UPnPAllowed int
	UPnPAll     bool
}

// Counts 返回当前封禁状态的计数。
func (b *Blocker) Counts() Counts {
	b.mu.Lock()
	defer b.mu.Unlock()

	c := Counts{ActiveBans: len(b.active), UPnPAll: b.upnpAll}
	// 与 Snapshot 一致，只统计值为 true 的条目（正常流程下解封会直接 delete）。
	for _, on := range b.fullBanned {
		if on {
			c.FullBanned++
		}
	}
	for _, on := range b.upnpBlocked {
		if on {
			c.UPnPBlocked++
		}
	}
	for _, on := range b.upnpAllowed {
		if on {
			c.UPnPAllowed++
		}
	}
	return c
}

// BanRule 标识一条端口级封禁规则；Family 为空表示同时覆盖 IPv4 与 IPv6（ban_both）。
type BanRule struct {
	MAC    string
	Port   uint16
	Proto  string
	Family string
}

// BanIndex 是封禁状态的只读索引，用于批量判定端口条目是否被封禁。
// 零值可用：不含任何规则，Banned 恒为 false。
type BanIndex struct {
	Both  bool                 // ban_both：端口级规则同时覆盖 IPv4 / IPv6
	Rules map[BanRule]struct{} // 端口级封禁规则
	Full  map[string]struct{}  // 处于全 UDP 端口封禁状态的设备 MAC
	allow map[uint16]struct{}  // 全端口封禁下仍放行的 UDP 端口
}

// Banned 判定某「设备 + 端口 + 协议 + 地址族」是否处于封禁状态：
// 设备级全 UDP 端口封禁生效期间，该设备除放行端口外的 UDP 端口均视为封禁；
// 命中端口级规则时即使在全端口封禁的放行端口内也视为封禁；
// ban_both 生效时端口级规则同时覆盖两个地址族。
func (ix BanIndex) Banned(mac string, port uint16, proto string, v6 bool) bool {
	if _, full := ix.Full[mac]; full && proto == protoUDP {
		if _, allowed := ix.allow[port]; !allowed {
			return true
		}
	}
	family := ""
	if !ix.Both {
		family = familyV4
		if v6 {
			family = familyV6
		}
	}
	_, ok := ix.Rules[BanRule{MAC: mac, Port: port, Proto: proto, Family: family}]
	return ok
}

// FullBanned 返回该设备是否处于全 UDP 端口封禁状态。
func (ix BanIndex) FullBanned(mac string) bool {
	_, ok := ix.Full[mac]
	return ok
}

// BanIndex 返回当前封禁状态的只读索引（与 Snapshot 不同，不做排序与展示格式化），
// 供 /devices、/device 之类的汇总 / 筛选接口判定端口封禁状态。
func (b *Blocker) BanIndex() BanIndex {
	// 与 Migrate / ForceUnban 同序加锁：先 migrateMu（保护 fw 指针），再 mu（保护封禁状态）。
	b.migrateMu.RLock()
	defer b.migrateMu.RUnlock()
	b.mu.Lock()
	defer b.mu.Unlock()

	ix := BanIndex{
		Both:  b.fw != nil && b.fw.BanBoth(),
		Rules: make(map[BanRule]struct{}, len(b.active)),
		Full:  make(map[string]struct{}, len(b.fullBanned)),
		allow: make(map[uint16]struct{}),
	}
	if b.fw != nil {
		for _, port := range b.fw.FullBanAllowPorts() {
			ix.allow[port] = struct{}{}
		}
	}
	for _, st := range b.active {
		family := ""
		if !ix.Both {
			family = st.family
		}
		ix.Rules[BanRule{MAC: st.mac, Port: st.port, Proto: st.proto, Family: family}] = struct{}{}
	}
	for mac, on := range b.fullBanned {
		if on {
			ix.Full[mac] = struct{}{}
		}
	}
	return ix
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
	b.maybeFullBan(mac, b.devIPOf(mac))
	return removed, firstErr
}
