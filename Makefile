APP     := pcdn-detect
LDFLAGS := -s -w

.PHONY: all build clean mipsle mips arm arm64 amd64

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) .

# OpenWrt 常见架构交叉编译（CGO_ENABLED=0，产出静态可执行文件）

# ramips / mt7621 (mipsel_24kc)
mipsle:
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP)-mipsle .

# ar71xx / ath79 (mips_24kc)
mips:
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP)-mips .

# armv7 (arm_cortex-a7)
arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP)-armv7 .

# armv8 (aarch64_cortex-a53)
arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP)-arm64 .

amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP)-amd64 .

clean:
	rm -rf bin
