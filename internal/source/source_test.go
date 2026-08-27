package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/q0tik/q0t-gates/internal/event"
)

func resolverFor(t *testing.T, raw string) *Resolver {
	t.Helper()
	ev, err := event.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return New(ev)
}

// Сообщение коммита должно доставаться одинаково независимо от способа коммита:
// иначе правило про атрибуцию ловит Bash и пропускает MCP.
func TestCommitMessageFromBash(t *testing.T) {
	cases := map[string]struct{ cmd, want string }{
		"двойные кавычки": {`git commit -m "fix: тест"`, "fix: тест"},
		"одинарные":       {`git commit -m 'fix: тест'`, "fix: тест"},
		"без кавычек":     {`git commit -m fix`, "fix"},
		"экранированная кавычка": {
			`git commit -m "он сказал \"ок\""`, `он сказал "ок"`},
		"два -m": {
			`git commit -m "заголовок" -m "тело"`, "заголовок\n\nтело"},
		"с флагами до -m": {`git commit --no-verify -m "x"`, "x"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := resolverFor(t, `{"tool_name":"Bash","tool_input":{"command":`+quote(c.cmd)+`}}`)
			if got := r.Get("commit_message"); got != c.want {
				t.Errorf("commit_message = %q, ждали %q", got, c.want)
			}
		})
	}
}

func TestCommitMessageFromMCP(t *testing.T) {
	r := resolverFor(t, `{"tool_name":"mcp__gitlab-qb__create_commit","tool_input":{"commit_message":"feat: из MCP"}}`)
	if got := r.Get("commit_message"); got != "feat: из MCP" {
		t.Errorf("commit_message = %q, ждали \"feat: из MCP\"", got)
	}
}

// Коммит без -m: сообщение придёт из редактора, движок его не видит.
// Пустая строка честнее выдумки — иначе require-правила ложно срабатывали бы.
func TestCommitMessageWithoutDashM(t *testing.T) {
	r := resolverFor(t, `{"tool_name":"Bash","tool_input":{"command":"git commit --amend"}}`)
	if got := r.Get("commit_message"); got != "" {
		t.Errorf("ждали пустую строку, получили %q", got)
	}
}

const transcriptJSONL = `{"isSidechain":false,"message":{"content":[{"type":"text","text":"смотрю BSGD-4382"}]}}
{"isSidechain":false,"message":{"content":[{"type":"tool_use","name":"Skill","input":{"skill":"postmortem"}}]}}
{"isSidechain":true,"message":{"content":[{"type":"tool_use","name":"mcp__telegram__tg_dialogs","input":{}}]}}
{"isSidechain":true,"message":{"content":[{"type":"text","text":"внутри субагента"}]}}
`

func transcriptResolver(t *testing.T, body string) *Resolver {
	t.Helper()
	p := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return resolverFor(t, `{"hook_event_name":"Stop","transcript_path":`+quote(p)+`}`)
}

// На разделении основного контекста и субагента держатся правила вида
// «тяжёлые чтения только через субагента» — если оно врёт, правила врут.
func TestTranscriptSeparatesSidechain(t *testing.T) {
	r := transcriptResolver(t, transcriptJSONL)

	main := r.Get("transcript")
	if !strings.Contains(main, "BSGD-4382") {
		t.Error("основной текст должен содержать сообщения основного контекста")
	}
	if strings.Contains(main, "внутри субагента") {
		t.Error("основной текст не должен содержать сообщения субагента")
	}
	if !strings.Contains(r.Get("transcript.all"), "внутри субагента") {
		t.Error("transcript.all должен содержать сообщения субагента")
	}

	mainTools := r.Get("transcript.tools")
	if !strings.Contains(mainTools, "Skill(postmortem)") {
		t.Errorf("Skill должен разворачиваться в Skill(<имя>), получили %q", mainTools)
	}
	if strings.Contains(mainTools, "tg_dialogs") {
		t.Error("инструменты субагента не должны попадать в transcript.tools")
	}
	if !strings.Contains(r.Get("transcript.tools.all"), "tg_dialogs") {
		t.Error("transcript.tools.all должен содержать инструменты субагента")
	}
}

func TestInSubagent(t *testing.T) {
	if got := transcriptResolver(t, transcriptJSONL).Get("in_subagent"); got != "true" {
		t.Errorf("последняя запись — субагентская, ждали true, получили %q", got)
	}
	main := `{"isSidechain":false,"message":{"content":[{"type":"text","text":"я в основном"}]}}` + "\n"
	if got := transcriptResolver(t, main).Get("in_subagent"); got != "false" {
		t.Errorf("последняя запись основная, ждали false, получили %q", got)
	}
}

// Отсутствующий транскрипт — обычная ситуация (PreToolUse в начале сессии).
// Движок обязан отдать пустое значение, а не упасть.
func TestMissingTranscript(t *testing.T) {
	r := resolverFor(t, `{"transcript_path":"/nope/nope.jsonl"}`)
	if r.Get("transcript") != "" || r.Get("in_subagent") != "false" {
		t.Error("отсутствующий транскрипт должен давать пустые значения без паники")
	}
}

func TestUnknownSourceIsEmpty(t *testing.T) {
	if got := resolverFor(t, `{}`).Get("нет-такого"); got != "" {
		t.Errorf("неизвестный источник должен давать пустую строку, получили %q", got)
	}
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("содержимое"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := resolverFor(t, `{"cwd":`+quote(dir)+`}`)
	if got := r.Get("file:x.txt"); got != "содержимое" {
		t.Errorf("file: должен читать относительно cwd, получили %q", got)
	}
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
