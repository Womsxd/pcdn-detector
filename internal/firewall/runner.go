package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner 执行一条外部命令；返回错误表示执行失败。供测试注入自定义实现。
type Runner func(name string, args ...string) error

// runCommand 返回带超时的真实命令执行器。
func runCommand(timeout time.Duration) Runner {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s：%v（输出：%s）", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
