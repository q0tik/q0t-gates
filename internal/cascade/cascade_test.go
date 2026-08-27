package cascade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/q0tik/q0t-gates/internal/rule"
)

func ruleBody(sev string) string {
	return `
description = "тест"
event    = "PreToolUse"
type     = "pattern"
severity = "` + sev + `"
message  = "нельзя"

[check]
source  = "command"
deny_if = 'rm -rf'
`
}

// tree строит дерево вида home/QB/service с правилами в указанных точках.
func tree(t *testing.T, files map[string]string) (home string) {
	t.Helper()
	home = t.TempDir()
	for rel, body := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestInheritsFromParent(t *testing.T) {
	home := tree(t, map[string]string{
		"QB/.claude/gates/no-rm.toml": ruleBody("block"),
	})
	got, errs := Collect("", filepath.Join(home, "QB", "service"), home, rule.PreToolUse)
	if len(errs) > 0 {
		t.Fatalf("ошибки загрузки: %v", errs)
	}
	if len(got) != 1 || got[0].ID != "no-rm" {
		t.Fatalf("правило из QB должно наследоваться в подпроект, получили %v", got)
	}
}

// Это ровно то, чего нет у хуков Claude Code и ради чего каскад написан вручную:
// правило ближе к файлу перекрывает правило выше.
func TestChildOverridesParent(t *testing.T) {
	home := tree(t, map[string]string{
		"QB/.claude/gates/no-rm.toml":         ruleBody("block"),
		"QB/service/.claude/gates/no-rm.toml": ruleBody("warn"),
	})
	got, _ := Collect("", filepath.Join(home, "QB", "service"), home, rule.PreToolUse)
	if len(got) != 1 {
		t.Fatalf("ждали одно правило после перекрытия, получили %d", len(got))
	}
	if got[0].Severity != rule.Warn {
		t.Errorf("severity = %q, ждали warn (перекрытие снизу)", got[0].Severity)
	}
}

func TestChildDisables(t *testing.T) {
	home := tree(t, map[string]string{
		"QB/.claude/gates/no-rm.toml": ruleBody("block"),
		"QB/service/.claude/gates/no-rm.toml": `
disabled = true
reason   = "здесь легитимно"
`,
	})
	got, _ := Collect("", filepath.Join(home, "QB", "service"), home, rule.PreToolUse)
	if len(got) != 0 {
		t.Errorf("выключенное правило не должно попадать в набор, получили %v", got)
	}
	// А в соседнем проекте оно продолжает действовать.
	got, _ = Collect("", filepath.Join(home, "QB", "other"), home, rule.PreToolUse)
	if len(got) != 1 {
		t.Errorf("выключение не должно протекать в соседний проект, получили %v", got)
	}
}

func TestGlobalIsLowestPriority(t *testing.T) {
	home := tree(t, map[string]string{
		"gates-global/no-rm.toml":     ruleBody("warn"),
		"QB/.claude/gates/no-rm.toml": ruleBody("block"),
	})
	got, _ := Collect(filepath.Join(home, "gates-global"), filepath.Join(home, "QB"), home, rule.PreToolUse)
	if len(got) != 1 || got[0].Severity != rule.Block {
		t.Errorf("проектное правило должно перекрывать глобальное, получили %v", got)
	}
}

func TestFiltersByEvent(t *testing.T) {
	home := tree(t, map[string]string{
		"QB/.claude/gates/no-rm.toml": ruleBody("block"),
	})
	got, _ := Collect("", filepath.Join(home, "QB"), home, rule.Stop)
	if len(got) != 0 {
		t.Errorf("правило PreToolUse не должно попадать в набор Stop, получили %v", got)
	}
}

// Подъём выше $HOME не выполняется: движок не должен подхватывать что-то из /
// или из чужой домашней директории.
func TestStopsAtHome(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(filepath.Join(base, ".claude", "gates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, ".claude", "gates", "no-rm.toml"), []byte(ruleBody("block")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	got, _ := Collect("", home, home, rule.PreToolUse)
	if len(got) != 0 {
		t.Errorf("правило выше $HOME не должно подхватываться, получили %v", got)
	}
}

func TestBrokenRuleDoesNotKillOthers(t *testing.T) {
	home := tree(t, map[string]string{
		"QB/.claude/gates/no-rm.toml":  ruleBody("block"),
		"QB/.claude/gates/broken.toml": "event = \"PreToolUse\"\n", // нет description/type/…
	})
	got, errs := Collect("", filepath.Join(home, "QB"), home, rule.PreToolUse)
	if len(errs) != 1 {
		t.Errorf("ждали одну ошибку загрузки, получили %v", errs)
	}
	if len(got) != 1 {
		t.Errorf("исправное правило должно остаться в наборе, получили %v", got)
	}
}

func TestHasAnyGatesFastPath(t *testing.T) {
	home := tree(t, map[string]string{
		"QB/.claude/gates/no-rm.toml": ruleBody("block"),
	})
	if !HasAnyGates("", filepath.Join(home, "QB", "deep", "deeper"), home) {
		t.Error("быстрый путь должен видеть правила выше по дереву")
	}
	other := t.TempDir()
	if HasAnyGates("", other, other) {
		t.Error("без правил быстрый путь должен давать false")
	}
}
