package firewall

import (
	"strconv"
	"strings"
)

// hookRun 运行 hook 命令模板。ban_both=true 时对 v4/v6 各执行一次，用 {family} 区分地址族；
// {proto} 为该次封禁的触发协议。若模板不含对应占位符，则该维度会重复执行同一命令，需确保命令幂等。
func (f *Firewall) hookRun(tpl, mac, ip string, port uint16, proto string) error {
	var firstErr error
	for _, family := range f.targetFamilies(ip) {
		if err := f.run("sh", "-c", renderCmd(tpl, mac, ip, port, family, proto)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// hookFullRun 运行全端口封禁的 hook 命令模板（{mac} 与 {ports} 占位符），仅执行一次。
func (f *Firewall) hookFullRun(tpl, mac string) error {
	return f.run("sh", "-c", renderFullBanCmd(tpl, mac, f.fullBanAllow))
}

// renderCmd 替换 hook 命令中的占位符。
func renderCmd(tpl, mac, ip string, port uint16, family, proto string) string {
	return strings.NewReplacer(
		"{mac}", mac,
		"{ip}", ip,
		"{port}", strconv.Itoa(int(port)),
		"{family}", family,
		"{proto}", proto,
	).Replace(tpl)
}

// renderFullBanCmd 替换全端口封禁 hook 命令中的占位符：{mac} 与 {ports}（放行端口逗号列表）。
func renderFullBanCmd(tpl, mac string, ports []uint16) string {
	return strings.NewReplacer(
		"{mac}", mac,
		"{ports}", portsCSV(ports),
	).Replace(tpl)
}

// renderUPnPCmd 替换 UPnP 拦截 hook 命令中的占位符：{mac} 与 {ports}（拦截目的端口逗号列表）。
func renderUPnPCmd(tpl, mac string, ports []uint16) string {
	return strings.NewReplacer(
		"{mac}", mac,
		"{ports}", portsCSV(ports),
	).Replace(tpl)
}

// renderUPnPAllCmd 替换 UPnP 全量拦截 hook 命令中的占位符：{ports}（拦截目的端口逗号列表）。
func renderUPnPAllCmd(tpl string, ports []uint16) string {
	return strings.NewReplacer(
		"{ports}", portsCSV(ports),
	).Replace(tpl)
}
