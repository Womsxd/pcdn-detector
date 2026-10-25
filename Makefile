APP       := pcdn-detect
PKG       := ./cmd/pcdn-detect
BUILDOPTS := -trimpath -buildvcs=false

# 版本信息：VERSION 为语义化版本号，GIT_HASH 默认取当前仓库短哈希
# （不在 git 仓库中或未安装 git 时回退为 unknown），可通过 -v/--version 查看。
VERSION  ?= 0.0.1-beta.1
GIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

LDFLAGS := -s -w -buildid= -X main.baseVersion=$(VERSION) -X main.gitHash=$(GIT_HASH)

# 可选构建参数：
#   TAGS=nohttp  编译不含 HTTP 功能的最小二进制（要求 [http] enabled = false）
#   SUFFIX=-nohttp  产物文件名后缀，便于与常规构建共存
TAGS   ?=
SUFFIX ?=

ifneq ($(TAGS),)
BUILDOPTS += -tags $(TAGS)
endif

.PHONY: all build clean mipsle mips arm arm64 amd64 nohttp nohttp-build

# 默认目标：OpenWrt 常见架构全量编译
all: mipsle mips arm arm64 amd64

build:
	CGO_ENABLED=0 go build $(BUILDOPTS) -ldflags "$(LDFLAGS)" -o bin/$(APP)$(SUFFIX) $(PKG)

# 无 HTTP 版本（-tags nohttp）：不编译 HTTP 传输层与 JSON 序列化，体积更小
nohttp:
	$(MAKE) TAGS=nohttp SUFFIX=-nohttp all

nohttp-build:
	$(MAKE) TAGS=nohttp SUFFIX=-nohttp build

# OpenWrt 常见架构交叉编译（CGO_ENABLED=0，产出静态可执行文件）

# ramips / mt7621 (mipsel_24kc)
mipsle:
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build $(BUILDOPTS) -ldflags "$(LDFLAGS)" -o bin/$(APP)-mipsle$(SUFFIX) $(PKG)

# ar71xx / ath79 (mips_24kc)
mips:
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build $(BUILDOPTS) -ldflags "$(LDFLAGS)" -o bin/$(APP)-mips$(SUFFIX) $(PKG)

# armv7 (arm_cortex-a7)
arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $(BUILDOPTS) -ldflags "$(LDFLAGS)" -o bin/$(APP)-armv7$(SUFFIX) $(PKG)

# armv8 (aarch64_cortex-a53)
arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILDOPTS) -ldflags "$(LDFLAGS)" -o bin/$(APP)-arm64$(SUFFIX) $(PKG)

amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILDOPTS) -ldflags "$(LDFLAGS)" -o bin/$(APP)-amd64$(SUFFIX) $(PKG)

clean:
	rm -rf bin
