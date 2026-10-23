package main

import "strings"

// 版本信息：baseVersion 为语义化版本号，gitHash 由构建时注入
// （make build 会传入 -ldflags "-X main.gitHash=<git 短哈希>"）。
var (
	baseVersion = "0.0.1-alpha"
	gitHash     = ""
)

// versionString 返回完整版本号：0.0.1-alpha-<git hash>。
// 未注入 git hash（如直接 go build）时以 unknown 占位，-v 仍可正常使用。
func versionString() string {
	hash := strings.TrimSpace(gitHash)
	if hash == "" {
		hash = "unknown"
	}
	return baseVersion + "-" + hash
}
