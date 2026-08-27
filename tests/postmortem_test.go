package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Правило на Stop — самое опасное из всех: ложное срабатывание не даёт закрыть
// сессию. Поэтому здесь случаев «не должно сработать» намеренно больше, чем
// «должно»: цена пропуска — незаписанный разбор, цена ложного срабатывания —
// выключенный движок.

// transcriptWith собирает JSONL-транскрипт из реплик основного контекста.
func transcriptWith(t *testing.T, texts []string, tools []string) string {
	t.Helper()
	var b strings.Builder
	for _, tx := range texts {
		rec := map[string]any{
			"type":        "user", // источник transcript.user берёт только реплики человека
			"isSidechain": false,
			"message": map[string]any{
				"role":    "user",
				"content": []map[string]any{{"type": "text", "text": tx}},
			},
		}
		line, _ := json.Marshal(rec)
		b.Write(line)
		b.WriteByte('\n')
	}
	for _, tool := range tools {
		block := map[string]any{"type": "tool_use", "name": tool, "input": map[string]any{}}
		if strings.HasPrefix(tool, "Skill(") {
			skill := strings.TrimSuffix(strings.TrimPrefix(tool, "Skill("), ")")
			block = map[string]any{"type": "tool_use", "name": "Skill",
				"input": map[string]any{"skill": skill}}
		}
		rec := map[string]any{
			"isSidechain": false,
			"message":     map[string]any{"content": []map[string]any{block}},
		}
		line, _ := json.Marshal(rec)
		b.Write(line)
		b.WriteByte('\n')
	}

	p := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPostmortemRequired(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ruleBody, err := os.ReadFile(filepath.Join(repoRoot, "library", "postmortem-required.toml"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(repoRoot, "checks", "postmortem_required.py"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		texts  []string
		tools  []string
		prompt string
		fires  bool
	}{
		{
			name:  "разбор инцидента без записи",
			texts: []string{"вчера янус лёг, разбираемся что случилось", "нашёл: проц падал на tz-aware datetime"},
			fires: true,
		},
		{
			name:  "прод упал, разбор не записан",
			texts: []string{"на проде сломался модуль 27, ордера не создавались с 14:00"},
			// один сильный сигнал («на проде сломал») достаточен
			fires: true,
		},
		{
			name:  "инцидент разобран через skill",
			texts: []string{"у нас инцидент с балансами, разбираем"},
			tools: []string{"Skill(postmortem)"},
			fires: false,
		},
		{
			name: "инцидент записан заметкой вне QB",
			texts: []string{
				"инцидент на домашнем сервере, adguard лёг",
				`mcp__obsidian__write_note {"path":"incidents/2026-08-27-adguard.md"}`,
			},
			fires: false,
		},
		{
			// 16 ложных «зафиксировано» из 25 реальных сессий пришли именно отсюда:
			// путь incidents/ постоянно встречается в related и в выдаче поиска.
			name: "путь incidents/ только упомянут, записи не было",
			texts: []string{
				"у нас инцидент с балансами, разбираемся",
				`mcp__obsidian__search_notes {"query":"баланс"}`,
				`результат: ["tasks/BSGD-4431", "incidents/mod27-manual-fallback"]`,
			},
			fires: true,
		},
		{
			name: "запись заметки в incidents/ засчитывается",
			texts: []string{
				"у нас инцидент с балансами, разбираемся",
				`mcp__obsidian__write_note {"path":"incidents/2026-08-27-balances.md","content":"…"}`,
			},
			fires: false,
		},
		{
			name:   "чужой инцидент, обойдён маркером",
			texts:  []string{"у Рамиля вчера была авария, посмотрим для понимания"},
			prompt: "это не мой инцидент [skip-postmortem]",
			fires:  false,
		},

		// Ниже — то, что НЕ должно срабатывать. Каждый случай взят из обычной
		// рабочей сессии, где слова-сигналы встречаются в мирном смысле.
		{
			name:  "обычная отладка теста",
			texts: []string{"тест упал, чиню фикстуру", "теперь зелёный"},
			fires: false,
		},
		{
			name:  "сборка не работает локально",
			texts: []string{"npm run build не работает, нет зависимости"},
			fires: false,
		},
		{
			name:  "обсуждение критичности фичи",
			texts: []string{"это критично для аналитиков, давай сделаем в первую очередь"},
			fires: false,
		},
		{
			name:  "пустая сессия",
			texts: []string{"привет, посмотри что тут"},
			fires: false,
		},
		{
			name:  "разработка самого движка правил",
			texts: []string{"добавляем в q0t-gates правило: у нас инцидент — значит нужен постмортем"},
			fires: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			// Ужесточаем до block, чтобы факт срабатывания был виден в решении.
			e.putRule("project", "postmortem-required.toml",
				strings.Replace(string(ruleBody), `severity = "warn"`, `severity = "block"`, 1))

			checksDir := filepath.Join(e.root, "checks")
			if err := os.MkdirAll(checksDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(checksDir, "postmortem_required.py"), script, 0o755); err != nil {
				t.Fatal(err)
			}

			ev, _ := json.Marshal(map[string]any{
				"hook_event_name": "Stop",
				"cwd":             e.project,
				"transcript_path": transcriptWith(t, c.texts, c.tools),
				"prompt":          c.prompt,
			})
			r := e.run(string(ev))

			got := r.decision() == "block"
			if got != c.fires {
				t.Errorf("сработало = %v, ждали %v\nstdout: %s", got, c.fires, r.stdout)
			}
		})
	}
}

// Судья дорогой и вызывается на каждом Stop, поэтому его [[match]] обязан
// отсекать сессии, в которых постмортема не было вовсе.
func TestPostmortemQualityMatchGate(t *testing.T) {
	repoRoot, _ := filepath.Abs("..")
	ruleBody, err := os.ReadFile(filepath.Join(repoRoot, "library", "postmortem-quality.toml"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		tools      []string
		judgeCalls bool
	}{
		{name: "постмортема не было", tools: nil, judgeCalls: false},
		{name: "постмортем писали", tools: []string{"Skill(postmortem)"}, judgeCalls: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.putRule("project", "postmortem-quality.toml", string(ruleBody))
			marker := filepath.Join(t.TempDir(), "called")
			fakeExe(t, "claude", "#!/bin/sh\ncat > /dev/null\ntouch "+marker+"\necho '{\"violated\": false}'\n")

			ev, _ := json.Marshal(map[string]any{
				"hook_event_name": "Stop",
				"cwd":             e.project,
				"transcript_path": transcriptWith(t, []string{"разбирали инцидент"}, c.tools),
			})
			e.run(string(ev))

			_, err := os.Stat(marker)
			called := err == nil
			if called != c.judgeCalls {
				t.Errorf("судья вызван = %v, ждали %v", called, c.judgeCalls)
			}
		})
	}
}
