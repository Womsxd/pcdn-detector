// Package state 定义重启继承所需的运行时状态，及其紧凑的二进制编解码与原子读写。
//
// 状态文件仅用于「reload 触发重启」时的封禁状态继承，属临时文件，默认落在系统临时目录。
// 二进制格式（自建，比 JSON 更小）：文件头 magic(4B) + version(u8) + CRC32(u32) + 负载长度(u32)，
// 负载为小端顺序编码的变长记录；IP 以原始字节存（IPv4 4B / IPv6 16B），MAC 6B。
package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"pcdn-detect/internal/netutil"
)

const (
	magic      = "PCST"
	version    = uint8(1)
	headerSize = 4 + 1 + 4 + 4 // magic + version + crc32 + payload length
	maxU16     = 1<<16 - 1
)

// 封禁条目的地址族取值（0 表示未区分）。
const (
	FamilyNone = uint8(0)
	FamilyV4   = uint8(1)
	FamilyV6   = uint8(2)
)

// File 是状态文件的顶层内容。
type File struct {
	Version       uint8
	SavedAtUnix   int64 // 保存时刻（Unix 秒）
	AlertSessions []AlertSession
	Block         BlockState
}

// AlertSession 是 detector 中一个处于告警中的「设备 + 端口 + 协议 + 地址族」会话。
type AlertSession struct {
	MAC            netutil.MAC
	Port           uint16
	Proto          uint8 // netutil.ProtoUDP / netutil.ProtoTCP
	V6             bool
	IP             netip.Addr
	AlertStartNano int64
	LastActiveNano int64
	ReportedCount  int
}

// BlockState 是 blocker 的封禁状态快照。
type BlockState struct {
	Bans        []BanEntry
	FullBanned  []FullBanEntry
	UPnPBlocked []netutil.MAC
	UPnPAllowed []netutil.MAC
	UPnPAll     bool
}

// BanEntry 是一条端口级封禁条目。
type BanEntry struct {
	MAC     netutil.MAC
	Port    uint16
	Proto   uint8
	Family  uint8 // FamilyNone / FamilyV4 / FamilyV6
	IP      netip.Addr
	Refs    int
	Applied bool
}

// FullBanEntry 是一个处于全 UDP 端口封禁中的设备。
type FullBanEntry struct {
	MAC netutil.MAC
	IP  netip.Addr
}

// Load 读取状态文件。文件不存在时返回 (nil, nil)；损坏时返回错误。
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	f, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("状态文件损坏：%w", err)
	}
	return f, nil
}

// Save 原子写入状态文件（临时文件 + rename），权限 0600。
func Save(path string, f *File) error {
	data, err := encode(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "pcdn-detect.state.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功后文件已被 rename，此处只清理失败残留
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Remove 删除状态文件；不存在时视为成功。
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func encode(f *File) ([]byte, error) {
	var p bytes.Buffer
	putI64(&p, f.SavedAtUnix)
	if err := putSessions(&p, f.AlertSessions); err != nil {
		return nil, err
	}
	if err := putBans(&p, f.Block.Bans); err != nil {
		return nil, err
	}
	if err := putFullBanned(&p, f.Block.FullBanned); err != nil {
		return nil, err
	}
	if err := putMACs(&p, f.Block.UPnPBlocked); err != nil {
		return nil, err
	}
	if err := putMACs(&p, f.Block.UPnPAllowed); err != nil {
		return nil, err
	}
	putU8(&p, boolByte(f.Block.UPnPAll))

	payload := p.Bytes()
	var out bytes.Buffer
	out.WriteString(magic)
	out.WriteByte(version)
	putU32(&out, crc32.ChecksumIEEE(payload))
	putU32(&out, uint32(len(payload)))
	out.Write(payload)
	return out.Bytes(), nil
}

func decode(data []byte) (*File, error) {
	if len(data) < headerSize {
		return nil, errors.New("文件长度不足")
	}
	if string(data[0:4]) != magic {
		return nil, errors.New("魔数不匹配")
	}
	if data[4] != version {
		return nil, fmt.Errorf("版本不支持：%d", data[4])
	}
	crc := binary.LittleEndian.Uint32(data[5:9])
	n := binary.LittleEndian.Uint32(data[9:13])
	body := data[headerSize:]
	if uint32(len(body)) != n {
		return nil, errors.New("负载长度不匹配")
	}
	if crc32.ChecksumIEEE(body) != crc {
		return nil, errors.New("CRC 校验失败")
	}

	r := &reader{b: body}
	f := &File{SavedAtUnix: r.i64()}
	f.AlertSessions = readSessions(r)
	f.Block.Bans = readBans(r)
	f.Block.FullBanned = readFullBanned(r)
	f.Block.UPnPBlocked = readMACs(r)
	f.Block.UPnPAllowed = readMACs(r)
	f.Block.UPnPAll = r.u8() != 0
	if r.err != nil {
		return nil, r.err
	}
	return f, nil
}

// ---- 写入 ----

func putU8(b *bytes.Buffer, v uint8) { b.WriteByte(v) }
func putU16(b *bytes.Buffer, v uint16) {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	b.Write(t[:])
}
func putU32(b *bytes.Buffer, v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	b.Write(t[:])
}
func putI64(b *bytes.Buffer, v int64) {
	var t [8]byte
	binary.LittleEndian.PutUint64(t[:], uint64(v))
	b.Write(t[:])
}

func putAddr(b *bytes.Buffer, a netip.Addr) {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		b.WriteByte(0)
	case a.Is4():
		b.WriteByte(4)
		x := a.As4()
		b.Write(x[:])
	case a.Is6():
		b.WriteByte(16)
		x := a.As16()
		b.Write(x[:])
	default:
		b.WriteByte(0)
	}
}

func putSessions(p *bytes.Buffer, ss []AlertSession) error {
	if len(ss) > maxU16 {
		return errors.New("告警会话数超出上限")
	}
	putU16(p, uint16(len(ss)))
	for _, s := range ss {
		p.Write(s.MAC[:])
		putU16(p, s.Port)
		putU8(p, s.Proto)
		putU8(p, boolByte(s.V6))
		putAddr(p, s.IP)
		putI64(p, s.AlertStartNano)
		putI64(p, s.LastActiveNano)
		putU32(p, uint32(s.ReportedCount))
	}
	return nil
}

func putBans(p *bytes.Buffer, bs []BanEntry) error {
	if len(bs) > maxU16 {
		return errors.New("封禁条目数超出上限")
	}
	putU16(p, uint16(len(bs)))
	for _, e := range bs {
		p.Write(e.MAC[:])
		putU16(p, e.Port)
		putU8(p, e.Proto)
		putU8(p, e.Family)
		putU8(p, boolByte(e.Applied))
		putU16(p, uint16(e.Refs))
		putAddr(p, e.IP)
	}
	return nil
}

func putFullBanned(p *bytes.Buffer, fs []FullBanEntry) error {
	if len(fs) > maxU16 {
		return errors.New("全端口封禁条目数超出上限")
	}
	putU16(p, uint16(len(fs)))
	for _, e := range fs {
		p.Write(e.MAC[:])
		putAddr(p, e.IP)
	}
	return nil
}

func putMACs(p *bytes.Buffer, ms []netutil.MAC) error {
	if len(ms) > maxU16 {
		return errors.New("MAC 条目数超出上限")
	}
	putU16(p, uint16(len(ms)))
	for _, m := range ms {
		p.Write(m[:])
	}
	return nil
}

// ---- 读取 ----

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) bytes(dst []byte) {
	if r.err != nil {
		return
	}
	if r.off+len(dst) > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	copy(dst, r.b[r.off:])
	r.off += len(dst)
}

func (r *reader) skip(n int) {
	if r.err != nil {
		return
	}
	if r.off+n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	r.off += n
}

func (r *reader) u8() uint8 {
	if r.err != nil {
		return 0
	}
	if r.off+1 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil {
		return 0
	}
	if r.off+2 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	if r.off+4 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) i64() int64 {
	if r.err != nil {
		return 0
	}
	if r.off+8 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := int64(binary.LittleEndian.Uint64(r.b[r.off:]))
	r.off += 8
	return v
}

func (r *reader) addr() netip.Addr {
	switch n := r.u8(); n {
	case 4:
		var x [4]byte
		r.bytes(x[:])
		if r.err != nil {
			return netip.Addr{}
		}
		return netip.AddrFrom4(x)
	case 16:
		var x [16]byte
		r.bytes(x[:])
		if r.err != nil {
			return netip.Addr{}
		}
		return netip.AddrFrom16(x)
	default:
		r.skip(int(n))
		return netip.Addr{}
	}
}

func readSessions(r *reader) []AlertSession {
	n := int(r.u16())
	if r.err != nil || n == 0 {
		return nil
	}
	ss := make([]AlertSession, 0, n)
	for i := 0; i < n; i++ {
		var s AlertSession
		r.bytes(s.MAC[:])
		s.Port = r.u16()
		s.Proto = r.u8()
		s.V6 = r.u8()&1 != 0
		s.IP = r.addr()
		s.AlertStartNano = r.i64()
		s.LastActiveNano = r.i64()
		s.ReportedCount = int(r.u32())
		if r.err != nil {
			return nil
		}
		ss = append(ss, s)
	}
	return ss
}

func readBans(r *reader) []BanEntry {
	n := int(r.u16())
	if r.err != nil || n == 0 {
		return nil
	}
	bs := make([]BanEntry, 0, n)
	for i := 0; i < n; i++ {
		var e BanEntry
		r.bytes(e.MAC[:])
		e.Port = r.u16()
		e.Proto = r.u8()
		e.Family = r.u8()
		e.Applied = r.u8()&1 != 0
		e.Refs = int(r.u16())
		e.IP = r.addr()
		if r.err != nil {
			return nil
		}
		bs = append(bs, e)
	}
	return bs
}

func readFullBanned(r *reader) []FullBanEntry {
	n := int(r.u16())
	if r.err != nil || n == 0 {
		return nil
	}
	fs := make([]FullBanEntry, 0, n)
	for i := 0; i < n; i++ {
		var e FullBanEntry
		r.bytes(e.MAC[:])
		e.IP = r.addr()
		if r.err != nil {
			return nil
		}
		fs = append(fs, e)
	}
	return fs
}

func readMACs(r *reader) []netutil.MAC {
	n := int(r.u16())
	if r.err != nil || n == 0 {
		return nil
	}
	ms := make([]netutil.MAC, 0, n)
	for i := 0; i < n; i++ {
		var m netutil.MAC
		r.bytes(m[:])
		if r.err != nil {
			return nil
		}
		ms = append(ms, m)
	}
	return ms
}

func boolByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}
