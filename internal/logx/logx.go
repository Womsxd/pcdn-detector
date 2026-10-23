// Package logx 在标准库 log 之上提供带等级的日志输出：
// 低于当前等级的日志不做格式化、不写终端，避免刷屏与无谓的字符串拼接。
//
// 等级由 [log] level 配置项决定（默认 warn）。封禁 / 解封等业务事件为 Info，
// 使其在默认等级下静默、需要排查时把等级调成 info 即可看到。
package logx

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync/atomic"
)

// Level 是日志输出等级，数值越大越严重。
type Level int32

const (
	LevelDebug Level = iota // 调试信息
	LevelInfo               // 常规信息（检测告警、封禁 / 解封、启动参数等）
	LevelWarn               // 警告（配置项被忽略、命令失败但不致命等）
	LevelError              // 错误（封禁 / 解封失败等）
)

// 等级名（配置项 [log] level 的取值）。
const (
	LevelNameDebug = "debug"
	LevelNameInfo  = "info"
	LevelNameWarn  = "warn"
	LevelNameError = "error"
)

// String 返回等级名（用于日志展示）。
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return LevelNameDebug
	case LevelInfo:
		return LevelNameInfo
	case LevelWarn:
		return LevelNameWarn
	case LevelError:
		return LevelNameError
	default:
		return "unknown"
	}
}

// ParseLevel 解析等级名（不区分大小写；warning 视为 warn）。
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case LevelNameDebug:
		return LevelDebug, nil
	case LevelNameInfo:
		return LevelInfo, nil
	case LevelNameWarn, "warning":
		return LevelWarn, nil
	case LevelNameError:
		return LevelError, nil
	default:
		return LevelWarn, fmt.Errorf("日志等级无效：%q（可选 debug / info / warn / error）", s)
	}
}

// Logger 是带等级过滤的日志器：内部复用标准库 log 的格式化与输出。
type Logger struct {
	l     *log.Logger
	level atomic.Int32
}

// New 创建日志器。等级默认 LevelDebug（全部输出），由调用方按配置调用 SetLevel。
func New(out io.Writer, prefix string, flag int) *Logger {
	lg := &Logger{l: log.New(out, prefix, flag)}
	lg.level.Store(int32(LevelDebug))
	return lg
}

// SetLevel 更新当前输出等级（可运行时热更新）。
func (lg *Logger) SetLevel(l Level) {
	if lg == nil {
		return
	}
	lg.level.Store(int32(l))
}

// Level 返回当前输出等级。
func (lg *Logger) Level() Level {
	if lg == nil {
		return LevelDebug
	}
	return Level(lg.level.Load())
}

// Enabled 判断该等级的日志是否会被输出。
func (lg *Logger) Enabled(l Level) bool {
	return lg != nil && l >= lg.Level()
}

// Std 返回内部的标准库 logger，供需要 *log.Logger 的第三方组件使用（如 HTTP 错误日志）。
func (lg *Logger) Std() *log.Logger {
	if lg == nil {
		return nil
	}
	return lg.l
}

// logf 按等级过滤后输出；lg 为 nil 时静默（调用方无需判空）。
func (lg *Logger) logf(l Level, format string, args ...any) {
	if !lg.Enabled(l) {
		return
	}
	lg.l.Printf(format, args...)
}

// Debugf 输出 debug 级日志。
func (lg *Logger) Debugf(format string, args ...any) { lg.logf(LevelDebug, format, args...) }

// Infof 输出 info 级日志（检测告警、封禁 / 解封等业务事件）。
func (lg *Logger) Infof(format string, args ...any) { lg.logf(LevelInfo, format, args...) }

// Warnf 输出 warn 级日志。
func (lg *Logger) Warnf(format string, args ...any) { lg.logf(LevelWarn, format, args...) }

// Errorf 输出 error 级日志。
func (lg *Logger) Errorf(format string, args ...any) { lg.logf(LevelError, format, args...) }

// Printf 等价于 Infof，保留标准库风格的调用写法。
func (lg *Logger) Printf(format string, args ...any) { lg.logf(LevelInfo, format, args...) }

// Println 等价于 Info 级的 Println。
func (lg *Logger) Println(v ...any) {
	if !lg.Enabled(LevelInfo) {
		return
	}
	lg.l.Println(v...)
}

// Fatalf 始终输出（不受等级影响）并退出进程。
func (lg *Logger) Fatalf(format string, args ...any) {
	if lg == nil {
		return
	}
	lg.l.Fatalf(format, args...)
}
