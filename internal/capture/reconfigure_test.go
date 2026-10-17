package capture

import (
	"io"
	"log"
	"os"
	"testing"
	"time"

	"pcdn-detect/internal/config"
	"pcdn-detect/internal/detector"
)

func testDetector() *detector.Detector {
	return detector.NewDetector(20, time.Minute, time.Minute, nil, log.New(io.Discard, "", 0), false, false, 0)
}

// netIfaceExists 判断本机是否存在指定网卡。
func netIfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

// Reconfigure 覆盖：协议变更走既有 socket（SetBPF）、环形缓冲变更重开 socket、非法网卡报错且保留旧 socket。
// 需要 root（CAP_NET_RAW）与 lo 网卡，否则跳过。
func TestCapturerReconfigure(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限打开 AF_PACKET")
	}
	if !netIfaceExists("lo") {
		t.Skip("缺少 lo 网卡")
	}

	base := config.CaptureConfig{Interface: "lo", FrameSize: 65536, BlockSize: 262144, NumBlocks: 8, Protocol: config.ProtoModeUDP}
	c, err := NewCapturer("lo", false, base, testDetector())
	if err != nil {
		t.Skipf("打开 lo 失败：%v", err)
	}
	defer c.Close()

	// 协议变更：在既有 socket 上重设 BPF。
	protoChanged := base
	protoChanged.Protocol = config.ProtoModeAll
	if err := c.Reconfigure(protoChanged, false); err != nil {
		t.Fatalf("协议变更失败：%v", err)
	}
	if got := c.ring.CaptureProto(); got != config.ProtoModeAll {
		t.Fatalf("协议应更新为 all，got %q", got)
	}

	// snaplen 变更：环形缓冲不变，仅重设 BPF。
	snapChanged := protoChanged
	snapChanged.Snaplen = 512
	if err := c.Reconfigure(snapChanged, false); err != nil {
		t.Fatalf("snaplen 变更失败：%v", err)
	}
	if got := c.ring.SnaplenValue(); got != 512 {
		t.Fatalf("snaplen 应更新为 512，got %d", got)
	}

	// 环形缓冲变更：重开 socket。
	ringChanged := snapChanged
	ringChanged.NumBlocks = 16
	if err := c.Reconfigure(ringChanged, false); err != nil {
		t.Fatalf("环形缓冲变更（重开 socket）失败：%v", err)
	}
	if frame, block, blocks := c.ring.RingParams(); frame != 65536 || block != 262144 || blocks != 16 {
		t.Fatalf("环形缓冲未更新：%d/%d/%d", frame, block, blocks)
	}

	// 非法网卡：应报错并保留旧 socket（不影响后续使用）。
	bad := ringChanged
	bad.Interface = "no-such-iface-xyz"
	if err := c.Reconfigure(bad, false); err == nil {
		t.Fatalf("不存在的网卡应报错")
	}
	if c.iface != "lo" {
		t.Fatalf("失败后应保留旧网卡，got %q", c.iface)
	}
}
