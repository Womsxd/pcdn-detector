package main

import "testing"

// -c/--config 的四种写法都应被识别，且取最先出现者。
func TestExtractConfigFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{"short space", []string{"-c", "a.toml"}, "a.toml", true},
		{"long space", []string{"--config", "b.toml"}, "b.toml", true},
		{"long eq", []string{"--config=c.toml"}, "c.toml", true},
		{"short eq", []string{"-c=d.toml"}, "d.toml", true},
		{"single dash long", []string{"-config", "e.toml"}, "e.toml", true},
		{"absent", []string{"-i", "br-lan"}, "", false},
		{"missing value", []string{"-c"}, "", false},
		{"first wins", []string{"-c", "first.toml", "--config", "second.toml"}, "first.toml", true},
	}
	for _, c := range cases {
		got, ok := extractConfigFlag(c.args)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: extractConfigFlag(%v) = (%q,%v)，期望 (%q,%v)", c.name, c.args, got, ok, c.want, c.ok)
		}
	}
}
