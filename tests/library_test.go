package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Каждое правило склада обязано иметь и срабатывающий, и не срабатывающий случай.
// Правило без обоих — это правило, про которое никто не знает, что оно делает:
// именно так набор правил за пару месяцев становится неревьюируемым.
type ruleCase struct {
	name  string
	event map[string]any
	// staged — содержимое git diff --staged, если правило смотрит туда
	staged string
	// remote — вывод git remote -v, если правило опознаёт репозиторий по факту
	remote string
	fires  bool
}

// toBlock ужесточает правило до block, чтобы срабатывание было видно в решении.
// Через регексп, а не заменой точной строки: выравнивание полей в TOML — вопрос
// вкуса автора правила, и тест не должен от него зависеть.
var reSeverityWarn = regexp.MustCompile(`(?m)^severity(\s*)=(\s*)"warn"`)

func toBlock(body string) string {
	return reSeverityWarn.ReplaceAllString(body, `severity$1=$2"block"`)
}

func bashCommit(cwd, msg string) map[string]any {
	return map[string]any{
		"hook_event_name": "PreToolUse",
		"cwd":             cwd,
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": `git commit -m "` + msg + `"`},
	}
}

func mcpTool(cwd, tool string, input map[string]any) map[string]any {
	return map[string]any{
		"hook_event_name": "PreToolUse",
		"cwd":             cwd,
		"tool_name":       tool,
		"tool_input":      input,
	}
}

func TestLibraryRules(t *testing.T) {
	libRoot, err := filepath.Abs("../library")
	if err != nil {
		t.Fatal(err)
	}

	suites := map[string][]ruleCase{
		"no-llm-attribution": {
			{name: "чистый коммит", event: bashCommit("", "fix: обычный коммит"), fires: false},
			{name: "Co-Authored-By", event: bashCommit("", `fix: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>`), fires: true},
			{name: "Generated with", event: bashCommit("", `fix: x\n\nGenerated with [Claude Code]`), fires: true},
			{name: "коммит через MCP", event: mcpTool("", "mcp__gitlab-qb__create_commit",
				map[string]any{"commit_message": "feat: x\n\nCo-Authored-By: Claude"}), fires: true},
			{name: "слово claude в тексте", event: bashCommit("", "fix: правка промпта для claude"), fires: false},
		},

		"jira-search-fields": {
			{name: "с fields", event: mcpTool("", "mcp__jira__jira_search_issues",
				map[string]any{"jql": "project = BSGD", "fields": "key,summary,status"}), fires: false},
			{name: "без fields", event: mcpTool("", "mcp__jira__jira_search_issues",
				map[string]any{"jql": "project = BSGD"}), fires: true},
			{name: "fields пустой", event: mcpTool("", "mcp__jira__jira_search_issues",
				map[string]any{"jql": "x", "fields": ""}), fires: true},
			{name: "fields списком", event: mcpTool("", "mcp__jira__jira_search_issues",
				map[string]any{"jql": "x", "fields": []string{"key", "summary"}}), fires: false},
			{name: "другой инструмент Jira", event: mcpTool("", "mcp__jira__jira_get_issue",
				map[string]any{"key": "BSGD-1"}), fires: false},
		},

		"telegram-via-agent": {
			{name: "из основного контекста", event: mcpTool("", "mcp__telegram__tg_dialogs", map[string]any{}), fires: true},
			{name: "отправка из основного", event: mcpTool("", "mcp__telegram__tg_send",
				map[string]any{"peer": "x", "text": "y"}), fires: true},
			{name: "не telegram", event: mcpTool("", "mcp__obsidian__read_note",
				map[string]any{"path": "x.md"}), fires: false},
		},

		"heavy-reads-via-subagent": {
			{name: "история Slack из основного", event: mcpTool("", "mcp__slack__conversations_history",
				map[string]any{"channel": "C1"}), fires: true},
			{name: "поиск Jira из основного", event: mcpTool("", "mcp__jira__jira_search_issues",
				map[string]any{"jql": "x", "fields": "key"}), fires: true},
			{name: "точечное чтение тикета", event: mcpTool("", "mcp__jira__jira_get_issue",
				map[string]any{"key": "BSGD-1"}), fires: false},
		},

		// Ответ на возражение «модель не склеит два факта»: принадлежность
		// репозитория определяется его remote, а не выводом модели и не тем,
		// в каком каталоге он лежит.
		"qb-no-llm-attribution": {
			{name: "рабочий remote, грязный коммит",
				event:  bashCommit("", `fix: x\n\nCo-Authored-By: Claude`),
				remote: "origin\thttps://gitlab.loc/bsgd/pisya3.git (fetch)", fires: true},
			{name: "рабочий remote, чистый коммит",
				event:  bashCommit("", "fix: обычный"),
				remote: "origin\thttps://gitlab.loc/bsgd/pisya3.git (fetch)", fires: false},
			{name: "личный remote, тот же грязный коммит",
				event:  bashCommit("", `fix: x\n\nCo-Authored-By: Claude`),
				remote: "origin\tgit@github.com:q0tik/pet.git (fetch)", fires: false},
			{name: "remote qbrains",
				event:  bashCommit("", `fix: x\n\nCo-Authored-By: Claude`),
				remote: "origin\thttps://docker-hub.qbrains.tech/x.git (fetch)", fires: true},
		},

		"no-secrets-staged": {
			{name: "обычный код", event: bashCommit("", "feat: x"),
				staged: "--- a/main.go\n+++ b/main.go\n+func main() {}\n", fires: false},
			{name: ".env", event: bashCommit("", "feat: x"),
				staged: "--- /dev/null\n+++ b/.env\n+SECRET=1\n", fires: true},
			{name: "config/local.env", event: bashCommit("", "feat: x"),
				staged: "--- /dev/null\n+++ b/config/local.env\n+A=1\n", fires: true},
			{name: "приватный ключ", event: bashCommit("", "feat: x"),
				staged: "--- /dev/null\n+++ b/deploy/server.pem\n+-----BEGIN\n", fires: true},
			{name: "id_rsa", event: bashCommit("", "feat: x"),
				staged: "--- /dev/null\n+++ b/.ssh/id_rsa\n+x\n", fires: true},
			{name: "environment.ts не секрет", event: bashCommit("", "feat: x"),
				staged: "--- /dev/null\n+++ b/src/environment.ts\n+export const x = 1\n", fires: false},
			{name: "обход маркером", event: bashCommit("", "feat: x [allow-env]"),
				staged: "--- /dev/null\n+++ b/config/local.env.template\n+A=\n", fires: false},
		},
	}

	for id, cases := range suites {
		src := filepath.Join(libRoot, id+".toml")
		if _, err := os.Stat(src); err != nil {
			t.Errorf("правило %s описано в тестах, но отсутствует на складе", id)
			continue
		}
		for _, c := range cases {
			t.Run(id+"/"+c.name, func(t *testing.T) {
				e := newEnv(t)
				body, err := os.ReadFile(src)
				if err != nil {
					t.Fatal(err)
				}
				// Правила склада заезжают в warn; для проверки факта срабатывания
				// ужесточаем до block, чтобы решение было видно в ответе.
				e.putRule("project", id+".toml", toBlock(string(body)))

				ev := c.event
				ev["cwd"] = e.project
				if c.staged != "" || c.remote != "" {
					fakeGit(t, c.staged, c.remote)
				}
				raw, _ := json.Marshal(ev)
				r := e.run(string(raw))

				got := r.decision() == "deny"
				if got != c.fires {
					t.Errorf("сработало = %v, ждали %v\nstdout: %s", got, c.fires, r.stdout)
				}
			})
		}
	}

	// Набор случаев может жить в отдельном файле, если правило сложное и требует
	// собственных фикстур. Список явный: молчаливое исключение вернуло бы ровно
	// ту дыру, которую эта проверка закрывает.
	coveredElsewhere := map[string]string{
		"postmortem-required": "postmortem_test.go",
		"postmortem-quality":  "postmortem_test.go",
		// Правило завязано на реальное дерево ~/Developer/QB и реальный реестр:
		// в изолированном окружении e2e его не воспроизвести честно, поэтому
		// проверяется прогоном самого скрипта (см. ниже, TestRegistryCheckScript).
		"registry-covers-repos": "registry_test.go",
	}

	// Обратная проверка: на складе не должно быть правил без набора случаев.
	entries, err := os.ReadDir(libRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		if !strings.HasSuffix(f.Name(), ".toml") {
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".toml")
		if _, ok := suites[id]; ok {
			continue
		}
		if _, ok := coveredElsewhere[id]; ok {
			continue
		}
		t.Errorf("правило %s лежит на складе без golden-случаев — добавь их в library_test.go", id)
	}
}

// fakeGit подкладывает git-обёртку, отвечающую по подкоманде: поднимать
// настоящий репозиторий с индексом и remote ради проверки регекспа — лишнее.
func fakeGit(t *testing.T, diff, remote string) {
	t.Helper()
	binDir := filepath.Join(t.TempDir(), "fakebin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case "$1" in
  diff)   cat <<'EOF_DIFF'
` + diff + `
EOF_DIFF
;;
  remote) cat <<'EOF_REMOTE'
` + remote + `
EOF_REMOTE
;;
  *) ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
