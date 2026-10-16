package state

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pcdn-detect/internal/netutil"
)

func mac(t *testing.T, s string) netutil.MAC {
	t.Helper()
	m, err := netutil.ParseMAC(s)
	if err != nil {
		t.Fatalf("解析 MAC %q 失败：%v", s, err)
	}
	return m
}

func sampleFile(t *testing.T) *File {
	t.Helper()
	return &File{
		Version:     version,
		SavedAtUnix: 1700000000,
		AlertSessions: []AlertSession{
			{
				MAC: mac(t, "aa:bb:cc:dd:ee:ff"), Port: 40000, Proto: netutil.ProtoUDP, V6: false,
				IP: netip.MustParseAddr("192.168.1.10"), AlertStartNano: 111, LastActiveNano: 222, ReportedCount: 7,
			},
			{
				MAC: mac(t, "11:22:33:44:55:66"), Port: 5000, Proto: netutil.ProtoTCP, V6: true,
				IP: netip.MustParseAddr("2408:8240:9411:37b0::1"), AlertStartNano: 333, LastActiveNano: 444, ReportedCount: 0,
			},
		},
		Block: BlockState{
			Bans: []BanEntry{
				{MAC: mac(t, "aa:bb:cc:dd:ee:ff"), Port: 40000, Proto: netutil.ProtoUDP, Family: FamilyV4, IP: netip.MustParseAddr("192.168.1.10"), Refs: 2, Applied: true},
				{MAC: mac(t, "11:22:33:44:55:66"), Port: 5000, Proto: netutil.ProtoTCP, Family: FamilyV6, IP: netip.MustParseAddr("2408:8240:9411:37b0::1"), Refs: 1, Applied: false},
			},
			FullBanned:  []FullBanEntry{{MAC: mac(t, "aa:bb:cc:dd:ee:ff"), IP: netip.MustParseAddr("192.168.1.10")}},
			UPnPBlocked: []netutil.MAC{mac(t, "22:33:44:55:66:77")},
			UPnPAllowed: []netutil.MAC{mac(t, "33:44:55:66:77:88")},
			UPnPAll:     true,
		},
	}
}

// Save→Load 二进制往返应保持全部字段。
func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pcdn-detect.state")
	want := sampleFile(t)
	if err := Save(path, want); err != nil {
		t.Fatalf("保存失败：%v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if got == nil {
		t.Fatalf("加载结果不应为 nil")
	}
	if len(got.AlertSessions) != len(want.AlertSessions) || len(got.Block.Bans) != len(want.Block.Bans) {
		t.Fatalf("条目数不符：%d/%d", len(got.AlertSessions), len(got.Block.Bans))
	}
	if got.AlertSessions[0].MAC != want.AlertSessions[0].MAC ||
		got.AlertSessions[0].AlertStartNano != want.AlertSessions[0].AlertStartNano ||
		got.AlertSessions[0].ReportedCount != want.AlertSessions[0].ReportedCount {
		t.Fatalf("会话[0] 不符：%+v", got.AlertSessions[0])
	}
	if got.AlertSessions[1].IP != want.AlertSessions[1].IP || !got.AlertSessions[1].V6 {
		t.Fatalf("会话[1] 不符：%+v", got.AlertSessions[1])
	}
	if got.Block.Bans[0].Applied != true || got.Block.Bans[1].Family != FamilyV6 {
		t.Fatalf("封禁条目不符：%+v", got.Block.Bans)
	}
	if !got.Block.UPnPAll || len(got.Block.UPnPBlocked) != 1 || got.Block.UPnPBlocked[0] != want.Block.UPnPBlocked[0] {
		t.Fatalf("UPnP 状态不符：%+v", got.Block)
	}
}

// 空状态也应可往返。
func TestStateEmptyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pcdn-detect.state")
	if err := Save(path, &File{Version: version, SavedAtUnix: time.Now().Unix()}); err != nil {
		t.Fatalf("保存失败：%v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if got == nil || len(got.AlertSessions) != 0 || len(got.Block.Bans) != 0 {
		t.Fatalf("空状态不符：%+v", got)
	}
}

// 不存在的文件返回 (nil, nil)。
func TestStateMissing(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.state"))
	if err != nil || got != nil {
		t.Fatalf("缺失文件应返回 (nil,nil)，got (%v,%v)", got, err)
	}
}

// 损坏 / 版本不符 / 魔数错误应返回错误。
func TestStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pcdn-detect.state")
	if err := Save(path, sampleFile(t)); err != nil {
		t.Fatalf("保存失败：%v", err)
	}
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败：%v", err)
	}

	// 篡改负载（触发 CRC 失败）。
	bad := append([]byte(nil), orig...)
	bad[len(bad)-1] ^= 0xff
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("CRC 损坏应报错")
	}

	// 错误魔数。
	bad = append([]byte(nil), orig...)
	copy(bad[0:4], "XXXX")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("魔数错误应报错")
	}

	// 版本不符。
	bad = append([]byte(nil), orig...)
	bad[4] = 99
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("版本不符应报错")
	}
}

// Remove 对不存在的文件应成功。
func TestStateRemoveMissing(t *testing.T) {
	if err := Remove(filepath.Join(t.TempDir(), "nope.state")); err != nil {
		t.Fatalf("删除缺失文件应成功：%v", err)
	}
}
