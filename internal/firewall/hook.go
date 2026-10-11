package firewall

import (
	"strconv"
	"strings"
)

// hookRun 运行端口封禁的 hook 命令模板（[firewall.hook] cmd）。
// action 为 ban / unban；ban_both=true 时对 v4/v6 各执行一次，用 {family} 区分地址族；
// {proto} 为该次封禁的触发协议。若模板不含对应占位符，则该维度会重复执行同一命令，需确保命令幂等。
func (f *Firewall) hookRun(action, mac, ip string, port uint16, proto string) error {
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		if err := f.run("sh", "-c", renderCmd(f.hookCmd, action, mac, ip, port, family, proto)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// hookFullRun 运行全端口封禁的 hook 命令模板（[full_ban.hook] cmd）。
// action 为 ban / unban；对 v4/v6 各执行一次（用 {family} 区分），ip 为设备本次触发时的 IP
// （仅当其地址族与 {family} 一致时填入，否则为空）。占位符：{action} {mac} {ip} {family} {ports}。
func (f *Firewall) hookFullRun(action, mac, ip string) error {
	var firstErr error
	for _, family := range []string{familyV4, familyV6} {
		cmd := renderFullBanCmd(f.fullBanHookCmd, action, mac, ipForFamily(ip, family), family, f.fullBanAllow)
		if err := f.run("sh", "-c", cmd); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// hookUPnPRun 运行 UPnP 拦截的 hook 命令模板（[upnp.hook] cmd）。
// action 为 ban / unban / block-all / unblock-all / allow / disallow；对 v4/v6 各执行一次
// （用 {family} 区分），ip 为设备已知 IP（仅当其地址族与 {family} 一致时填入，否则为空）。
// 占位符：{action} {mac} {ip} {family} {ports}。
func (f *Firewall) hookUPnPRun(action, mac, ip string) error {
	var firstErr error
	for _, family := range []string{familyV4, familyV6} {
		cmd := renderUPnPCmd(f.upnpHookCmd, action, mac, ipForFamily(ip, family), family, f.upnpPorts)
		if err := f.run("sh", "-c", cmd); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ipForFamily 返回与指定地址族匹配时使用的 IP 占位符值：ip 为空或属于另一地址族时返回空串。
func ipForFamily(ip, family string) string {
	if ip == "" || AddrFamily(ip) != family {
		return ""
	}
	return ip
}

// renderCmd 替换端口封禁 hook 命令中的占位符：{action} {mac} {ip} {port} {family} {proto}。
func renderCmd(tpl, action, mac, ip string, port uint16, family, proto string) string {
	return strings.NewReplacer(
		"{action}", action,
		"{mac}", mac,
		"{ip}", ip,
		"{port}", strconv.Itoa(int(port)),
		"{family}", family,
		"{proto}", proto,
	).Replace(tpl)
}

// renderFullBanCmd 替换全端口封禁 hook 命令中的占位符：{action} {mac} {ip} {family} {ports}。
func renderFullBanCmd(tpl, action, mac, ip, family string, ports []uint16) string {
	return strings.NewReplacer(
		"{action}", action,
		"{mac}", mac,
		"{ip}", ip,
		"{family}", family,
		"{ports}", portsCSV(ports),
	).Replace(tpl)
}

// renderUPnPCmd 替换 UPnP 拦截 hook 命令中的占位符：{action} {mac} {ip} {family} {ports}。
// 全量拦截 / 解除时 {mac} / {ip} 为空。
func renderUPnPCmd(tpl, action, mac, ip, family string, ports []uint16) string {
	return strings.NewReplacer(
		"{action}", action,
		"{mac}", mac,
		"{ip}", ip,
		"{family}", family,
		"{ports}", portsCSV(ports),
	).Replace(tpl)
}
