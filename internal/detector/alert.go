package detector

import (
	"fmt"
	"strings"
	"time"

	"pcdn-detect/internal/netutil"
	"pcdn-detect/internal/util"
)

// alertLogMaxIPs 是单条告警日志最多列出的对端 IP 数。peer_limit = 0 时单个端口可能有数万对端，
// 全量格式化会刷屏（logd / 串口）并瞬时占用大量内存。日志只列前 N 个，并注明真实总数。
const alertLogMaxIPs = 20

// checkPort 根据端口当前情况判定并输出告警。
// 首次达到阈值输出「疑似产生PCDN行为」；随后进入持续期：
//   - 只要该端口仍有流量（任意对端，无论新旧），就按最近活动时间刷新计时器；
//   - 期间出现新的对端 IP（哪怕只有 1 个）时额外输出「持续产生PCDN行为」；
//
// 持续期不再要求窗口内对端数达到阈值；若持续 alertDuration 内都没有任何流量，
// 则输出「PCDN行为结束」并结束本轮，之后可重新触发。
//
// mac / key 为该端口所属设备与端口的 map 键；v6 为该端口所属的地址族（决定设备 IP 的格式化
// 方式）。设备 MAC、端口号、协议、地址族均由此取得，无需在 device / portStat 内重复保存。
func checkPort[K peerKey](d *Detector, mac netutil.MAC, key portKey, ps *portStat[K], v6 bool, now time.Time) {
	proto := protoName(key.proto)
	if ps.alertStartNano == 0 {
		// 未处于告警中：窗口内对端数达到阈值才触发。
		if ps.peers.count() < d.threshold {
			return
		}
		ps.alertStartNano = now.UnixNano()
		// 只格式化要展示的前 N 个：peer_limit = 0 时对端可能有数万，全量格式化会刷屏。
		ips, totalPeers := ps.peers.headIPs(alertLogMaxIPs)
		d.alerts++
		d.logger.Printf("%s(%s) 的端口 %d(%s) 疑似产生PCDN行为（近 %s 内 %d 个对端IP，累计上行 %s / 下行 %s），相关IP为%s: %s",
			util.MaskDeviceMAC(d.hide, mac.String()), util.MaskDeviceIP(d.hide, ps.deviceIP(v6).String()), key.port, proto, d.window, totalPeers, util.HumanBytes(ps.upBytes), util.HumanBytes(ps.downBytes), truncatedNote(totalPeers, len(ips)), strings.Join(ips, ", "))
		if d.sink != nil {
			d.sink.OnAlertStart(mac.String(), ps.deviceIP(v6).String(), key.port, proto)
		}
		if d.lowMemory {
			// 低内存模式：清空对端列表并停止记录新对端，仅保留触发状态与累计计数。
			ps.reportedCount = totalPeers
			ps.peers.clear()
		} else {
			// 本轮初始已提示集合 = 当前窗口内全部对端（标记复用 peer.reported，零额外分配）。
			ps.reportedCount = ps.peers.markAllReported()
		}
		return
	}

	// 持续期内只要仍有流量，就按最近活动时间续期：避免对端流量仍在持续时，
	// 仅因没有新对端 IP 而被误判为「PCDN行为结束」。
	if ps.lastActiveNano > ps.alertStartNano {
		ps.alertStartNano = ps.lastActiveNano
	}

	// 持续期内长时间没有任何流量：本轮结束，允许后续重新触发。
	if now.UnixNano()-ps.alertStartNano > int64(d.alertDuration) {
		d.logger.Printf("%s(%s) 的端口 %d(%s) PCDN行为结束（本轮累计 %d 个对端IP，累计上行 %s / 下行 %s）",
			util.MaskDeviceMAC(d.hide, mac.String()), util.MaskDeviceIP(d.hide, ps.deviceIP(v6).String()), key.port, proto, ps.reportedCount, util.HumanBytes(ps.upBytes), util.HumanBytes(ps.downBytes))
		if d.sink != nil {
			d.sink.OnAlertEnd(mac.String(), ps.deviceIP(v6).String(), key.port, proto)
		}
		ps.alertStartNano = 0
		ps.peers.clearReported()
		ps.reportedCount = 0
		return
	}

	// 期间出现新对端 IP 时额外输出「持续产生PCDN行为」（计时器已由流量续期）。
	// 仅在真正需要展示时才把 netip.Addr 转成字符串，且只格式化前 N 个。
	newKeys := ps.peers.collectNewReported()
	if len(newKeys) == 0 {
		return
	}
	ps.reportedCount += len(newKeys)
	newIPs, _ := formatIPs(newKeys, alertLogMaxIPs)
	d.alerts++
	d.logger.Printf("%s(%s) 的端口 %d(%s) 持续产生PCDN行为（本轮累计 %d 个对端IP，累计上行 %s / 下行 %s），新增相关IP为%s: %s",
		util.MaskDeviceMAC(d.hide, mac.String()), util.MaskDeviceIP(d.hide, ps.deviceIP(v6).String()), key.port, proto, ps.reportedCount, util.HumanBytes(ps.upBytes), util.HumanBytes(ps.downBytes), truncatedNote(len(newKeys), len(newIPs)), strings.Join(newIPs, ", "))
}

// truncatedNote 返回日志中「IP 列表被截断」的说明，未截断时为空。
func truncatedNote(total, shown int) string {
	if total <= shown {
		return ""
	}
	return fmt.Sprintf("（共 %d 个，仅列前 %d 个）", total, shown)
}
