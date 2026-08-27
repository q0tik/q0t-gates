// Команда gate — единственная точка входа движка правил.
//
// Регистрируется один раз глобально в ~/.claude/settings.json на все события.
// Активность определяется не настройками, а наличием файлов правил в дереве:
// подключить движок к проекту = положить туда файл правила.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/q0tik/q0t-gates/internal/audit"
	"github.com/q0tik/q0t-gates/internal/cascade"
	"github.com/q0tik/q0t-gates/internal/check"
	"github.com/q0tik/q0t-gates/internal/event"
	"github.com/q0tik/q0t-gates/internal/rule"
	"github.com/q0tik/q0t-gates/internal/source"
	"github.com/q0tik/q0t-gates/internal/verdict"
)

func main() {
	// Fail-open как первое и последнее слово: гейт, который ломает работу
	// собственным багом, будет отключён целиком в первый же день, и защиты
	// не останется вовсе.
	defer func() {
		if r := recover(); r != nil {
			audit.Write(auditDir(), audit.Record{
				Verdict: audit.Error,
				Reason:  fmt.Sprintf("panic: %v", r),
			})
			os.Exit(0)
		}
	}()

	if os.Getenv("CLAUDE_GATES_DISABLE") != "" {
		os.Exit(0)
	}

	ev, err := event.Parse(os.Stdin)
	if err != nil {
		audit.Write(auditDir(), audit.Record{Verdict: audit.Error, Reason: "разбор события: " + err.Error()})
		os.Exit(0)
	}

	home, _ := os.UserHomeDir()
	root := repoRoot()
	globalDir := filepath.Join(root, "global")
	start := ev.CascadeRoot()

	// Быстрый путь: только stat по цепочке директорий, без чтения файлов.
	if !cascade.HasAnyGates(globalDir, start, home) {
		os.Exit(0)
	}

	evName := rule.Event(ev.HookEventName)
	rules, errs := cascade.Collect(globalDir, start, home, evName)
	for _, e := range errs {
		// Битое правило не должно ронять остальные — но и молчать о нём нельзя.
		audit.Write(auditDir(), audit.Record{
			Event: ev.HookEventName, Verdict: audit.Error,
			CWD: ev.CWD, Session: ev.SessionID, Reason: e.Error(),
		})
	}
	if len(rules) == 0 {
		os.Exit(0)
	}

	res := source.New(ev)
	var findings []verdict.Finding

	for _, r := range rules {
		if !matches(r, ev, res) {
			continue
		}

		out := check.Run(r, ev, res, root)
		if out.Err != nil {
			v := audit.Error
			if r.Type == rule.Judge {
				v = audit.JudgeFailed
			}
			audit.Write(auditDir(), rec(r, ev, v, out.Err.Error(), ""))
			if r.FailClosed {
				findings = append(findings, verdict.Finding{
					Rule: r, Reason: "проверка не выполнилась (fail_closed): " + out.Err.Error(),
				})
			}
			continue
		}
		if !out.Violated {
			continue
		}

		if r.Escape != nil {
			if src := res.Get(r.Escape.Source); strings.Contains(src, r.Escape.Marker) {
				v := audit.Escaped
				// Маркер в сообщении коммита мог вписать сам агент. Обход
				// пропускается, но помечается отдельно — иначе движок тихо
				// выродится в декорацию, которую агент отключает себе сам.
				if r.Escape.Source == "commit_message" && !sanctionedByUser(res, r.Escape.Marker) {
					v = audit.EscapedByAgent
				}
				audit.Write(auditDir(), rec(r, ev, v, out.Reason, r.Escape.Source))
				continue
			}
		}

		audit.Write(auditDir(), rec(r, ev, audit.Violated, out.Reason, ""))
		findings = append(findings, verdict.Finding{Rule: r, Reason: out.Reason})
	}

	os.Exit(verdict.Emit(os.Stdout, evName, findings))
}

// matches — сработал ли хоть один блок [[match]]. Пустой набор блоков означает
// «всегда на этом событии».
func matches(r *rule.Rule, ev *event.Event, res *source.Resolver) bool {
	if len(r.Match) == 0 {
		return true
	}
	for _, m := range r.Match {
		if matchBlock(m, ev, res) {
			return true
		}
	}
	return false
}

// matchBlock — все условия внутри блока по И.
func matchBlock(m rule.Match, ev *event.Event, res *source.Resolver) bool {
	if len(m.Tool) > 0 && !toolMatches(m.Tool, ev.ToolName) {
		return false
	}
	for name, re := range m.Sources {
		if !re.MatchString(res.Get(name)) {
			return false
		}
	}
	return true
}

// toolMatches сверяет имя инструмента со списком, поддерживая glob.
// Без glob каждый новый MCP-сервер тихо открывает дыру в каждом правиле.
func toolMatches(patterns []string, name string) bool {
	if name == "" {
		return false
	}
	for _, p := range patterns {
		if p == name {
			return true
		}
		if strings.ContainsAny(p, "*?[") {
			if ok, err := filepath.Match(p, name); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// sanctionedByUser — есть ли в сообщениях пользователя санкция на обход.
//
// Ищем маркер или явное разрешение в тексте пользователя: если человек сам
// написал маркер в промпте, обход законен и в журнале не помечается особо.
func sanctionedByUser(res *source.Resolver, marker string) bool {
	return strings.Contains(res.Get("prompt"), marker) ||
		reUserSanction.MatchString(res.Get("transcript"))
}

var reUserSanction = regexp.MustCompile(`(?i)\[(allow|skip)-[a-z0-9-]+\]`)

func rec(r *rule.Rule, ev *event.Event, v audit.Verdict, reason, escSrc string) audit.Record {
	return audit.Record{
		Rule: r.ID, Event: ev.HookEventName, Verdict: v,
		Severity: string(r.Severity), CWD: ev.CWD, Session: ev.SessionID,
		Reason: reason, EscapeSource: escSrc, RulePath: r.Path,
	}
}

// repoRoot — корень установки q0t-gates: рядом с бинарём, на уровень выше bin/.
func repoRoot() string {
	if v := os.Getenv("Q0T_GATES_ROOT"); v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(filepath.Dir(exe))
}

func auditDir() string { return filepath.Join(repoRoot(), "audit") }
