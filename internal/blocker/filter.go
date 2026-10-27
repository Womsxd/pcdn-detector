package blocker

import (
	"fmt"

	"pcdn-detect/internal/filter"
)

func (b *Blocker) SetFilter(f *filter.DeviceFilter) error {
	b.migrateMu.Lock()
	defer b.migrateMu.Unlock()
	b.filter = f

	b.mu.Lock()
	targets := make(map[string]*banState)
	for key, st := range b.active {
		if !f.Allow(st.mac, st.port) {
			targets[key] = st
		}
	}
	b.mu.Unlock()

	var firstErr error
	devices := make(map[string]struct{})
	for key, st := range targets {
		if st.applied && b.fw != nil {
			if err := b.fw.Unban(st.mac, st.ip(), st.port, st.proto); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("更新名单时解封端口 %d 失败：%w", st.port, err)
				}
				continue
			}
		}
		b.mu.Lock()
		delete(b.active, key)
		b.bumpPortLocked(st.mac, st.port, -1)
		b.mu.Unlock()
		devices[st.mac] = struct{}{}
	}
	for mac := range devices {
		b.maybeFullBan(mac, b.devIPOf(mac))
	}
	return firstErr
}
