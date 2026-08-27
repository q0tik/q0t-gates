package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Тесты на type = "script" и type = "judge".
//
// Обе проверки запускают внешний процесс, поэтому здесь важны не столько
// счастливые пути, сколько поведение при поломке: движок обязан пропускать
// действие и оставлять след, а не блокировать работу из-за упавшего скрипта
// или молчащего судьи.

// fakeExe кладёт в PATH исполняемый файл с заданным именем и телом.
func fakeExe(t *testing.T, name, script string) {
	t.Helper()
	binDir := filepath.Join(t.TempDir(), "fakebin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// putCheckScript кладёт скрипт в checks/ внутри корня установки движка —
// туда, где его ищет относительный путь из правила.
func (e *env) putCheckScript(name, body string) {
	e.t.Helper()
	dir := filepath.Join(e.root, "checks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func stopEvent(cwd string) string {
	b, _ := json.Marshal(map[string]any{
		"hook_event_name": "Stop",
		"session_id":      "test",
		"cwd":             cwd,
		"transcript_path": "/nope",
	})
	return string(b)
}

const scriptRule = `
description = "проверка скриптом"
event    = "Stop"
type     = "script"
severity = "block"
message  = "скрипт сказал нет"

[check]
script = "checks/probe.sh"
`

func TestScriptViolation(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "probe.toml", scriptRule)
	e.putCheckScript("probe.sh", "#!/bin/sh\necho '{\"violated\": true, \"reason\": \"причина от скрипта\"}'\n")

	r := e.run(stopEvent(e.project))
	if r.decision() != "block" {
		t.Fatalf("ждали block, получили %q; stdout=%s", r.decision(), r.stdout)
	}
	if !strings.Contains(r.stdout, "причина от скрипта") {
		t.Errorf("reason скрипта должен доезжать до агента: %s", r.stdout)
	}
	if recs := e.auditRecords(); len(recs) != 1 || recs[0]["verdict"] != "violated" {
		t.Errorf("ждали violated в журнале, получили %v", recs)
	}
}

func TestScriptNoViolation(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "probe.toml", scriptRule)
	e.putCheckScript("probe.sh", "#!/bin/sh\necho '{\"violated\": false}'\n")

	r := e.run(stopEvent(e.project))
	if r.stdout != "" {
		t.Errorf("при violated=false движок должен молчать: %q", r.stdout)
	}
}

// Скрипт получает событие и уже вычисленные источники — иначе нестандартная
// проверка упиралась бы в набор источников движка.
func TestScriptReceivesEventAndSources(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "probe.toml", scriptRule)
	dump := filepath.Join(t.TempDir(), "stdin.json")
	e.putCheckScript("probe.sh", "#!/bin/sh\ncat > "+dump+"\necho '{\"violated\": false}'\n")

	e.run(stopEvent(e.project))

	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("скрипт не получил stdin: %v", err)
	}
	var payload struct {
		Event   map[string]any    `json:"event"`
		Sources map[string]string `json:"sources"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("payload скрипта не разбирается: %v\n%s", err, b)
	}
	if payload.Event["hook_event_name"] != "Stop" {
		t.Errorf("исходное событие должно доезжать целиком: %v", payload.Event)
	}
	if _, ok := payload.Sources["transcript.tools"]; !ok {
		t.Errorf("вычисленные источники должны приходить скрипту: %v", payload.Sources)
	}
}

func TestScriptFailuresFailOpen(t *testing.T) {
	cases := map[string]string{
		"ненулевой код":      "#!/bin/sh\necho 'что-то пошло не так' >&2\nexit 1\n",
		"мусор на stdout":    "#!/bin/sh\necho 'не json'\n",
		"пустой вывод":       "#!/bin/sh\n",
		"скрипт отсутствует": "",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.putRule("project", "probe.toml", scriptRule)
			if body != "" {
				e.putCheckScript("probe.sh", body)
			}

			r := e.run(stopEvent(e.project))
			if r.decision() != "" {
				t.Errorf("поломка скрипта не должна блокировать работу, получили %q", r.decision())
			}
			recs := e.auditRecords()
			if len(recs) != 1 || recs[0]["verdict"] != "error" {
				t.Errorf("поломка обязана попасть в журнал как error, получили %v", recs)
			}
		})
	}
}

// fail_closed — осознанный отказ от fail-open для отдельного правила.
func TestScriptFailClosed(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "probe.toml", "fail_closed = true\n"+scriptRule)
	e.putCheckScript("probe.sh", "#!/bin/sh\nexit 1\n")

	r := e.run(stopEvent(e.project))
	if r.decision() != "block" {
		t.Errorf("при fail_closed поломка обязана блокировать, получили %q", r.decision())
	}
}

const judgeRule = `
description = "оценка качества судьёй"
event    = "Stop"
type     = "judge"
severity = "ask"
message  = "судья недоволен"

[check]
model   = "haiku"
input   = ["transcript"]
timeout = 5
prompt  = "оцени"
`

func TestJudgeViolation(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "judge.toml", judgeRule)
	fakeExe(t, "claude", "#!/bin/sh\necho '{\"violated\": true, \"reason\": \"причина от судьи\"}'\n")

	r := e.run(stopEvent(e.project))
	if r.decision() != "block" {
		t.Fatalf("ask на Stop должен останавливать сессию, получили %q; stdout=%s", r.decision(), r.stdout)
	}
	if !strings.Contains(r.stdout, "причина от судьи") {
		t.Errorf("reason судьи должен доезжать: %s", r.stdout)
	}
}

// Модель часто оборачивает JSON в ограду или предваряет фразой — ронять
// правило из-за этого не стоит.
func TestJudgeOutputVariants(t *testing.T) {
	cases := map[string]struct {
		out   string
		fires bool
	}{
		"чистый json":       {`{"violated": true, "reason": "x"}`, true},
		"в markdown-ограде": {"```json\n{\"violated\": true, \"reason\": \"x\"}\n```", true},
		"с преамбулой":      {`Вот мой вывод: {"violated": true, "reason": "x"}`, true},
		"violated false":    {`{"violated": false, "reason": ""}`, false},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.putRule("project", "judge.toml", judgeRule)
			fakeExe(t, "claude", "#!/bin/sh\ncat > /dev/null\ncat <<'EOF'\n"+c.out+"\nEOF\n")

			got := e.run(stopEvent(e.project)).decision() == "block"
			if got != c.fires {
				t.Errorf("сработало = %v, ждали %v", got, c.fires)
			}
		})
	}
}

// Судья не должен уметь заблокировать работу собственной поломкой.
func TestJudgeFailuresDoNotBlock(t *testing.T) {
	cases := map[string]string{
		"мусор вместо json": "#!/bin/sh\necho 'я подумал и решил, что всё хорошо'\n",
		"ненулевой код":     "#!/bin/sh\nexit 3\n",
		"таймаут":           "#!/bin/sh\nsleep 30\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.putRule("project", "judge.toml", judgeRule)
			fakeExe(t, "claude", body)

			r := e.run(stopEvent(e.project))
			if r.decision() != "" {
				t.Errorf("поломка судьи не должна блокировать, получили %q", r.decision())
			}
			recs := e.auditRecords()
			if len(recs) != 1 || recs[0]["verdict"] != "judge_failed" {
				t.Errorf("ждали judge_failed в журнале, получили %v", recs)
			}
		})
	}
}

// Судья запускается через claude -p; если бы он наследовал обычное окружение,
// его собственные вызовы инструментов снова пришли бы в движок.
func TestJudgeRunsWithGatesDisabled(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "judge.toml", judgeRule)
	dump := filepath.Join(t.TempDir(), "env.txt")
	fakeExe(t, "claude", "#!/bin/sh\ncat > /dev/null\necho \"$CLAUDE_GATES_DISABLE\" > "+dump+"\necho '{\"violated\": false}'\n")

	e.run(stopEvent(e.project))

	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		t.Errorf("судья должен запускаться с CLAUDE_GATES_DISABLE=1, получили %q", b)
	}
}

// Судья дорогой: он не должен вызываться, если [[match]] не сошёлся.
func TestJudgeNotCalledWhenMatchFails(t *testing.T) {
	e := newEnv(t)
	e.putRule("project", "judge.toml", judgeRule+"\n[[match]]\n\"transcript.tools\" = 'Skill\\(postmortem\\)'\n")
	marker := filepath.Join(t.TempDir(), "called")
	fakeExe(t, "claude", "#!/bin/sh\ntouch "+marker+"\necho '{\"violated\": true}'\n")

	e.run(stopEvent(e.project)) // транскрипта нет → инструментов нет → match не сойдётся

	if _, err := os.Stat(marker); err == nil {
		t.Error("судья вызван, хотя [[match]] не сошёлся — это лишние деньги и секунды на каждом Stop")
	}
}
