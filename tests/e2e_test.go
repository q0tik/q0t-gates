// Пакет tests прогоняет собранный бинарь gate на настоящих событиях хука.
//
// Юнит-тесты проверяют части; здесь проверяется то, что видит Claude Code:
// код возврата, JSON на stdout и запись в журнал.
package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var gateBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gate-bin")
	if err != nil {
		panic(err)
	}
	gateBin = filepath.Join(dir, "gate")
	cmd := exec.Command("go", "build", "-o", gateBin, "../cmd/gate")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	t        *testing.T
	home     string
	root     string // корень установки q0t-gates
	project  string
	auditDir string
}

// newEnv собирает изолированное дерево: свой $HOME, свой корень движка, проект.
func newEnv(t *testing.T) *env {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, "q0t-gates")
	project := filepath.Join(home, "proj")
	for _, d := range []string{filepath.Join(root, "global"), filepath.Join(project, ".claude", "gates")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &env{t: t, home: home, root: root, project: project, auditDir: filepath.Join(root, "audit")}
}

func (e *env) putRule(dir, name, body string) {
	e.t.Helper()
	var full string
	switch dir {
	case "global":
		full = filepath.Join(e.root, "global", name)
	default:
		full = filepath.Join(e.project, ".claude", "gates", name)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

type result struct {
	code   int
	stdout string
}

func (e *env) run(eventJSON string) result {
	e.t.Helper()
	cmd := exec.Command(gateBin)
	cmd.Stdin = strings.NewReader(eventJSON)
	cmd.Env = append(os.Environ(),
		"Q0T_GATES_ROOT="+e.root,
		"HOME="+e.home,
		"CLAUDE_GATES_DISABLE=",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	return result{code: cmd.ProcessState.ExitCode(), stdout: out.String()}
}

func (e *env) auditRecords() []map[string]any {
	e.t.Helper()
	entries, err := os.ReadDir(e.auditDir)
	if err != nil {
		return nil
	}
	var recs []map[string]any
	for _, f := range entries {
		b, err := os.ReadFile(filepath.Join(e.auditDir, f.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				recs = append(recs, m)
			}
		}
	}
	return recs
}

func (r result) decision() string {
	var m struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
		Decision string `json:"decision"`
	}
	json.Unmarshal([]byte(r.stdout), &m)
	if m.HookSpecificOutput.PermissionDecision != "" {
		return m.HookSpecificOutput.PermissionDecision
	}
	return m.Decision
}

const attrRule = `
description = "LLM-атрибуция в коммите"
event    = "PreToolUse"
type     = "pattern"
severity = "block"
message  = "Убери атрибуцию"

[[match]]
tool    = "Bash"
command = '^\s*git\s+commit\b'

[[match]]
tool = "mcp__gitlab-qb__*"

[check]
source  = "commit_message"
deny_if = '(?i)Co-Authored-By:\s*Claude'
`

func commitEvent(cwd, msg string) string {
	b, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "test-session",
		"cwd":             cwd,
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "git commit -m " + strconv(msg)},
	})
	return string(b)
}

func strconv(s string) string {
	b, _ := json.Marshal(s)
	return "\"" + strings.Trim(string(b), "\"") + "\""
}

func TestBlocksViolatingCommit(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)

	r := e.run(commitEvent(e.project, "fix: тест\n\nCo-Authored-By: Claude <noreply@anthropic.com>"))
	if r.code != 0 {
		t.Fatalf("хук должен завершаться нулём и решать через JSON, код = %d", r.code)
	}
	if got := r.decision(); got != "deny" {
		t.Fatalf("ждали deny, получили %q; stdout=%s", got, r.stdout)
	}
	if !strings.Contains(r.stdout, "Убери атрибуцию") {
		t.Errorf("сообщение правила должно доезжать до агента: %s", r.stdout)
	}

	recs := e.auditRecords()
	if len(recs) != 1 || recs[0]["verdict"] != "violated" {
		t.Errorf("ждали одну запись violated в журнале, получили %v", recs)
	}
}

func TestCleanCommitPasses(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)

	r := e.run(commitEvent(e.project, "fix: чистый коммит"))
	if r.stdout != "" {
		t.Errorf("чистый коммит не должен ничего печатать, получили %q", r.stdout)
	}
	if recs := e.auditRecords(); len(recs) != 0 {
		t.Errorf("passed не должен попадать в журнал, получили %v", recs)
	}
}

// Дыра, ради которой [[match]] сделан массивом: коммит через MCP мимо Bash-регекспа.
func TestCatchesCommitViaMCP(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)

	ev, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"cwd":             e.project,
		"tool_name":       "mcp__gitlab-qb__create_commit",
		"tool_input":      map[string]any{"commit_message": "feat: x\n\nCo-Authored-By: Claude"},
	})
	if got := e.run(string(ev)).decision(); got != "deny" {
		t.Fatalf("коммит через MCP должен ловиться так же, получили %q", got)
	}
}

func TestNoGatesNoOutput(t *testing.T) {
	e := newEnv(t)
	r := e.run(commitEvent(e.project, "Co-Authored-By: Claude"))
	if r.code != 0 || r.stdout != "" {
		t.Errorf("без правил движок обязан молчать: код=%d stdout=%q", r.code, r.stdout)
	}
}

func TestWarnDoesNotBlock(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml",
		strings.Replace(attrRule, `severity = "block"`, `severity = "warn"`, 1))

	r := e.run(commitEvent(e.project, "Co-Authored-By: Claude"))
	if got := r.decision(); got != "" {
		t.Errorf("warn не должен выносить решение, получили %q", got)
	}
	if !strings.Contains(r.stdout, "systemMessage") {
		t.Errorf("warn должен показывать сообщение: %s", r.stdout)
	}
	if recs := e.auditRecords(); len(recs) != 1 || recs[0]["verdict"] != "violated" {
		t.Errorf("warn должен писаться в журнал: %v", recs)
	}
}

func TestEscapeFromCommitMessage(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml",
		attrRule+"\n[escape]\nsource = \"commit_message\"\nmarker = \"[allow-attr]\"\n")

	r := e.run(commitEvent(e.project, "fix [allow-attr]\n\nCo-Authored-By: Claude"))
	if got := r.decision(); got != "" {
		t.Fatalf("обход должен пропускать действие, получили %q", got)
	}
	recs := e.auditRecords()
	if len(recs) != 1 {
		t.Fatalf("обход обязан оставлять след, получили %v", recs)
	}
	// Санкции пользователя в сессии не было — значит маркер вписал агент,
	// и это должно быть видно отдельно, а не слиться с законным обходом.
	if recs[0]["verdict"] != "escaped_by_agent" {
		t.Errorf("ждали escaped_by_agent, получили %v", recs[0]["verdict"])
	}
}

// Каскад: правило лежит выше по дереву, работа идёт в подпроекте.
func TestInheritance(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)
	deep := filepath.Join(e.project, "services", "accountant_web")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := e.run(commitEvent(deep, "Co-Authored-By: Claude")).decision(); got != "deny" {
		t.Errorf("правило проекта должно действовать в подпроекте, получили %q", got)
	}
}

func TestChildDisablesInheritedRule(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)
	deep := filepath.Join(e.project, "vendor-fork", ".claude", "gates")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(deep, "no-llm-attribution.toml"),
		[]byte("disabled = true\nreason = \"форк вендора\"\n"), 0o644)

	cwd := filepath.Join(e.project, "vendor-fork")
	if got := e.run(commitEvent(cwd, "Co-Authored-By: Claude")).decision(); got != "" {
		t.Errorf("выключенное правило не должно срабатывать, получили %q", got)
	}
}

// Гейт, который ломает работу собственным багом, отключат целиком — поэтому
// битое правило обязано пропускать действие и оставлять след.
func TestFailOpenOnBrokenRule(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "broken.toml", "event = \"PreToolUse\"\ntype = \"pattern\"\n")

	r := e.run(commitEvent(e.project, "любой"))
	if r.code != 0 || r.decision() != "" {
		t.Errorf("битое правило не должно блокировать: код=%d решение=%q", r.code, r.decision())
	}
	recs := e.auditRecords()
	if len(recs) != 1 || recs[0]["verdict"] != "error" {
		t.Errorf("битое правило обязано попасть в журнал как error, получили %v", recs)
	}
}

func TestMalformedEventFailsOpen(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)
	r := e.run("это не json")
	if r.code != 0 || r.decision() != "" {
		t.Errorf("мусор на stdin не должен блокировать работу: код=%d", r.code)
	}
}

// Stop отвечает другим форматом, чем PreToolUse.
func TestStopBlockFormat(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "must-report.toml", `
description = "отчёт не сдан"
event    = "Stop"
type     = "pattern"
severity = "block"
message  = "Сдай отчёт"

[check]
source  = "transcript"
require = 'session-report'
`)
	ev, _ := json.Marshal(map[string]any{
		"hook_event_name": "Stop",
		"cwd":             e.project,
		"transcript_path": "/nope",
	})
	r := e.run(string(ev))
	if r.decision() != "block" {
		t.Errorf("Stop должен отвечать decision=block, получили %q; stdout=%s", r.decision(), r.stdout)
	}
}

func TestDisableEnvVar(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "no-llm-attribution.toml", attrRule)

	cmd := exec.Command(gateBin)
	cmd.Stdin = strings.NewReader(commitEvent(e.project, "Co-Authored-By: Claude"))
	cmd.Env = append(os.Environ(), "Q0T_GATES_ROOT="+e.root, "HOME="+e.home, "CLAUDE_GATES_DISABLE=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	if out.String() != "" {
		t.Errorf("CLAUDE_GATES_DISABLE должен полностью выключать движок (иначе судья зациклится): %q", out.String())
	}
}
