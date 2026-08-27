// Package check выполняет проверку правила и возвращает вердикт.
package check

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/q0tik/q0t-gates/internal/event"
	"github.com/q0tik/q0t-gates/internal/rule"
	"github.com/q0tik/q0t-gates/internal/source"
)

// Result — исход проверки одного правила.
type Result struct {
	Violated bool
	Reason   string
	Err      error // ошибка исполнения проверки: правило считается не сработавшим
}

// Run выполняет проверку правила.
func Run(r *rule.Rule, ev *event.Event, res *source.Resolver, repoRoot string) Result {
	switch r.Type {
	case rule.Pattern:
		return runPattern(r, res)
	case rule.Script:
		return runScript(r, ev, res, repoRoot)
	case rule.Judge:
		return runJudge(r, res)
	}
	return Result{Err: fmt.Errorf("неизвестный type %q", r.Type)}
}

func runPattern(r *rule.Rule, res *source.Resolver) Result {
	val := res.Get(r.Check.Source)
	if r.Check.DenyIf != nil {
		if m := r.Check.DenyIf.FindString(val); m != "" {
			return Result{Violated: true, Reason: truncate(m, 200)}
		}
		return Result{}
	}
	if !r.Check.Require.MatchString(val) {
		return Result{Violated: true, Reason: "не найдено: " + truncate(r.Check.Require.String(), 200)}
	}
	return Result{}
}

// scriptVerdict — форма ответа, обязательная и для script, и для judge.
// Свободному тексту движок не доверяет: непарсимый ответ — это ошибка проверки,
// а не разрешение и не запрет.
type scriptVerdict struct {
	Violated bool   `json:"violated"`
	Reason   string `json:"reason"`
}

func runScript(r *rule.Rule, ev *event.Event, res *source.Resolver, repoRoot string) Result {
	path := r.Check.Script
	if !filepath.IsAbs(path) {
		path = filepath.Join(repoRoot, path)
	}

	// Скрипт получает исходное событие целиком плюс уже вычисленные источники —
	// чтобы нестандартная проверка не упиралась в набор источников движка.
	payload := map[string]any{
		"event":   ev.Raw,
		"sources": collectCommon(res),
	}
	in, err := json.Marshal(payload)
	if err != nil {
		return Result{Err: err}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	// Без WaitDelay отмена контекста убивает сам процесс, но не его потомков:
	// они держат унаследованные пайпы, и Wait() ждёт их закрытия — то есть
	// таймаут не работает вовсе. На Stop это подвешивает закрытие сессии.
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewReader(in)
	cmd.Dir = ev.CWD
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return Result{Err: fmt.Errorf("%s: %w: %s", filepath.Base(path), err, truncate(errb.String(), 300))}
	}

	var v scriptVerdict
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &v); err != nil {
		return Result{Err: fmt.Errorf("%s: непарсимый вердикт: %s", filepath.Base(path), truncate(out.String(), 200))}
	}
	return Result{Violated: v.Violated, Reason: v.Reason}
}

func runJudge(r *rule.Rule, res *source.Resolver) Result {
	var b bytes.Buffer
	b.WriteString(r.Check.Prompt)
	b.WriteString("\n\n--- ДАННЫЕ ---\n")
	for _, name := range r.Check.Input {
		b.WriteString("\n## " + name + "\n")
		b.WriteString(truncate(res.Get(name), 120000))
		b.WriteByte('\n')
	}
	b.WriteString("\nОтветь ТОЛЬКО валидным JSON вида {\"violated\": bool, \"reason\": \"<одна строка>\"}, без пояснений и без markdown-ограды.\n")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.Check.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "claude", "-p", "--model", r.Check.Model)
	cmd.WaitDelay = 2 * time.Second // см. комментарий в runScript
	cmd.Stdin = bytes.NewReader(b.Bytes())
	// Судья не должен наследовать хук-контекст: иначе его собственные вызовы
	// инструментов снова придут в движок и получится рекурсия.
	cmd.Env = append(os.Environ(), "CLAUDE_GATES_DISABLE=1")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return Result{Err: fmt.Errorf("судья: %w: %s", err, truncate(errb.String(), 200))}
	}

	v, err := parseJudgeOutput(out.Bytes())
	if err != nil {
		return Result{Err: err}
	}
	return Result{Violated: v.Violated, Reason: v.Reason}
}

// parseJudgeOutput выковыривает JSON из ответа судьи: модель нередко оборачивает
// его в ```json или предваряет фразой, и ронять правило из-за этого не стоит.
func parseJudgeOutput(b []byte) (scriptVerdict, error) {
	var v scriptVerdict
	trimmed := bytes.TrimSpace(b)
	if err := json.Unmarshal(trimmed, &v); err == nil {
		return v, nil
	}
	start := bytes.IndexByte(trimmed, '{')
	end := bytes.LastIndexByte(trimmed, '}')
	if start >= 0 && end > start {
		if err := json.Unmarshal(trimmed[start:end+1], &v); err == nil {
			return v, nil
		}
	}
	return v, fmt.Errorf("судья вернул непарсимый вердикт: %s", truncate(string(trimmed), 200))
}

// collectCommon отдаёт скрипту источники, которые дёшевы или уже вычислены.
// staged_diff сюда не входит намеренно: скрипт запросит его сам, если нужен.
func collectCommon(res *source.Resolver) map[string]string {
	names := []string{"command", "prompt", "commit_message", "transcript", "transcript.user", "transcript.tools", "in_subagent"}
	out := make(map[string]string, len(names))
	for _, n := range names {
		out[n] = res.Get(n)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
