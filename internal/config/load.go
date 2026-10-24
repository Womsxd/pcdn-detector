package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Result 描述一次配置加载的结果。
type Result struct {
	Config   *Config
	Path     string   // 实际使用的配置文件路径（创建时为新建文件）
	Created  bool     // 是否为本次新建的默认配置文件
	Warnings []string // 加载过程中被跳过的候选文件说明
}

// LoadConfig 按默认候选顺序加载配置（等价于 loadConfig(configCandidates, configCreateNames)）。
func LoadConfig() (*Result, error) {
	return loadConfig(configCandidates, configCreateNames)
}

// LoadConfigFor 在显式指定配置文件时仅使用该文件（且不自动创建），否则走默认候选顺序。
func LoadConfigFor(explicitPath string, hasExplicit bool) (*Result, error) {
	if hasExplicit {
		return loadExplicit(explicitPath)
	}
	return loadConfig(configCandidates, configCreateNames)
}

// LoadConfigStrict 只加载已存在的配置文件：显式指定时仅用该文件，否则按默认候选顺序查找。
// 找不到或解析失败都返回错误，绝不创建默认配置（供 --test-config 校验配置文件使用）。
func LoadConfigStrict(explicitPath string, hasExplicit bool) (*Result, error) {
	if hasExplicit {
		return loadExplicit(explicitPath)
	}
	return loadConfig(configCandidates, nil)
}

// loadExplicit 只加载显式指定的配置文件：不存在或解析失败都直接报错，不创建任何新文件。
func loadExplicit(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("指定的配置文件不存在：%s", path)
		}
		return nil, fmt.Errorf("读取配置文件 %s 失败：%w", path, err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败：%w", path, err)
	}
	cfg.applyDefaults()
	return &Result{Config: cfg, Path: path}, nil
}

// loadConfig 按 candidates 顺序查找并加载配置文件：
//   - 找到且解析成功：使用该配置；
//   - 存在但解析/读取失败：记录警告并继续尝试下一个候选；
//   - 全部候选都不可用：尝试创建 createNames 中的默认配置文件；
//   - 创建目标已存在导致无法创建：返回错误。
func loadConfig(candidates, createNames []string) (*Result, error) {
	var warnings []string
	for _, name := range candidates {
		data, err := os.ReadFile(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("读取配置文件 %s 失败，已跳过：%v", name, err))
			continue
		}
		cfg, err := parseConfig(data)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("解析配置文件 %s 失败，已跳过：%v", name, err))
			continue
		}
		cfg.applyDefaults()
		return &Result{Config: cfg, Path: name, Warnings: warnings}, nil
	}

	// createNames 为空表示「只校验、不创建」（见 LoadConfigStrict）。
	if len(createNames) == 0 {
		if len(warnings) > 0 {
			return nil, fmt.Errorf("没有可用的配置文件：%s", strings.Join(warnings, "；"))
		}
		return nil, fmt.Errorf("未找到配置文件（已查找：%s），请用 -c/--config 指定路径", strings.Join(candidates, "、"))
	}

	// 没有任何可加载的配置：创建默认配置文件。
	name, err := createDefaultConfig(createNames)
	if err != nil {
		if len(warnings) > 0 {
			return nil, fmt.Errorf("%v；且创建默认配置失败：%w", warnings[len(warnings)-1], err)
		}
		return nil, err
	}
	return &Result{Config: DefaultConfig(), Path: name, Created: true, Warnings: warnings}, nil
}

// WriteDefaultConfig 把内置默认配置模板写入已存在的 dir 目录，返回实际写入的文件路径。
// 目录不存在时报错（不自动创建）；目标文件已存在时报错（不覆盖）。
// 供 --init-config 在指定目录生成配置文件使用，不影响当前工作目录。
func WriteDefaultConfig(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("未指定要生成配置文件的目录")
	}
	st, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("目录不存在：%s（请先创建该目录）", dir)
		}
		return "", fmt.Errorf("检查目录 %s 失败：%w", dir, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s 不是目录", dir)
	}
	paths := make([]string, 0, len(configCreateNames))
	for _, name := range configCreateNames {
		p := filepath.Join(dir, name)
		// 先给出明确提示：目标文件已存在时不覆盖（createDefaultConfig 仍用 O_EXCL 兜底）。
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("%s 已存在，未覆盖（如需重新生成请先删除该文件）", p)
		}
		paths = append(paths, p)
	}
	return createDefaultConfig(paths)
}

// createDefaultConfig 依次尝试用 names 创建默认配置文件。
// 某个名字已存在时尝试下一个；若全部已存在或创建失败，则返回错误。
func createDefaultConfig(names []string) (string, error) {
	for _, name := range names {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // 名字被占用，尝试下一个
			}
			return "", fmt.Errorf("创建配置文件 %s 失败：%w", name, err)
		}
		if _, err := f.WriteString(defaultConfigTemplate); err != nil {
			f.Close()
			return "", fmt.Errorf("写入配置文件 %s 失败：%w", name, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("关闭配置文件 %s 失败：%w", name, err)
		}
		return name, nil
	}
	return "", fmt.Errorf("配置文件 %s 均已存在，无法创建默认配置", strings.Join(names, "/"))
}
