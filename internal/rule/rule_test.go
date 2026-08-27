package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const validPattern = `
description = "тест"
event    = "PreToolUse"
type     = "pattern"
severity = "block"
message  = "нельзя"

[[match]]
tool = "Bash"
command = '^git commit'

[check]
source  = "commit_message"
deny_if = 'Co-Authored-By'
`

func TestLoadValid(t *testing.T) {
	r, err := Load(write(t, "no-attr.toml", validPattern))
	if err != nil {
		t.Fatalf("не ожидали ошибку: %v", err)
	}
	if r.ID != "no-attr" {
		t.Errorf("id = %q, ждали no-attr (id берётся из имени файла)", r.ID)
	}
	if len(r.Match) != 1 || len(r.Match[0].Tool) != 1 || r.Match[0].Tool[0] != "Bash" {
		t.Errorf("match разобран неверно: %+v", r.Match)
	}
	if r.Check.DenyIf == nil || r.Check.Require != nil {
		t.Error("ждали deny_if без require")
	}
}

func TestToolAcceptsList(t *testing.T) {
	body := strings.Replace(validPattern, `tool = "Bash"`,
		`tool = ["Bash", "mcp__gitlab-qb__*"]`, 1)
	r, err := Load(write(t, "x.toml", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Match[0].Tool) != 2 {
		t.Errorf("ждали 2 инструмента, получили %v", r.Match[0].Tool)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"нет description": {
			strings.Replace(validPattern, `description = "тест"`, "", 1), "description"},
		"нет message": {
			strings.Replace(validPattern, `message  = "нельзя"`, "", 1), "message"},
		"неизвестный event": {
			strings.Replace(validPattern, `event    = "PreToolUse"`, `event = "Whatever"`, 1), "event"},
		"неизвестный type": {
			strings.Replace(validPattern, `type     = "pattern"`, `type = "magic"`, 1), "type"},
		"неизвестный severity": {
			strings.Replace(validPattern, `severity = "block"`, `severity = "maybe"`, 1), "severity"},
		"deny_if и require вместе": {
			validPattern + "\nrequire = 'x'\n", "deny_if"},
		"битый регексп": {
			strings.Replace(validPattern, `deny_if = 'Co-Authored-By'`, `deny_if = '('`, 1), "регексп"},
		"опечатка в корне": {
			"severty = \"block\"\n" + validPattern, "неизвестные поля"},
		"опечатка внутри check": {
			strings.Replace(validPattern, "deny_if = 'Co-Authored-By'",
				"deny_if = 'Co-Authored-By'\ndeny_iff = 'x'", 1), "неизвестные поля в [check]"},
		"disabled без reason": {
			"disabled = true\n", "reason"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, "x.toml", c.body))
			if err == nil {
				t.Fatal("ждали ошибку валидации, её нет")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ошибка %q не упоминает %q", err, c.want)
			}
		})
	}
}

// Ключевое ограничение безопасности: маркер обхода ищется только там, где пишет
// человек. Иначе агент упрётся в гейт, выпишет себе амнистию и поедет дальше.
func TestEscapeSourceRestricted(t *testing.T) {
	for _, src := range []string{"transcript", "command", "tool_input", "staged_diff"} {
		t.Run(src, func(t *testing.T) {
			body := validPattern + "\n[escape]\nsource = \"" + src + "\"\nmarker = \"[skip]\"\n"
			if _, err := Load(write(t, "x.toml", body)); err == nil {
				t.Fatalf("источник %q должен быть запрещён для escape", src)
			}
		})
	}
	for _, src := range []string{"prompt", "commit_message"} {
		t.Run(src+"_разрешён", func(t *testing.T) {
			body := validPattern + "\n[escape]\nsource = \"" + src + "\"\nmarker = \"[skip]\"\n"
			if _, err := Load(write(t, "x.toml", body)); err != nil {
				t.Fatalf("источник %q должен быть разрешён: %v", src, err)
			}
		})
	}
}

func TestJudgeDefaults(t *testing.T) {
	body := `
description = "тест"
event    = "Stop"
type     = "judge"
severity = "ask"
message  = "неполно"

[check]
prompt = "проверь"
`
	r, err := Load(write(t, "j.toml", body))
	if err != nil {
		t.Fatal(err)
	}
	if r.Check.Model != "haiku" || r.Check.Timeout != 30 {
		t.Errorf("ждали дефолты haiku/30, получили %q/%d", r.Check.Model, r.Check.Timeout)
	}
}
