// Package verdict переводит решения движка в формат ответа хука Claude Code.
package verdict

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/q0tik/q0t-gates/internal/rule"
)

// Finding — одно сработавшее правило.
type Finding struct {
	Rule   *rule.Rule
	Reason string
}

func (f Finding) text() string {
	s := "[" + f.Rule.ID + "] " + f.Rule.Message
	if f.Reason != "" {
		s += "\n  → " + f.Reason
	}
	return s
}

// Emit пишет ответ хука. Возвращает код выхода.
//
// Приоритет между сработавшими правилами: block > ask > warn. Правила одного
// уровня объединяются в одно сообщение — блокировать по одному, заставляя
// прогонять цикл заново на каждое, значит превращать движок в пытку.
func Emit(w io.Writer, ev rule.Event, findings []Finding) int {
	if len(findings) == 0 {
		return 0
	}

	var blocks, asks, warns []Finding
	for _, f := range findings {
		switch f.Rule.Severity {
		case rule.Block:
			blocks = append(blocks, f)
		case rule.Ask:
			asks = append(asks, f)
		default:
			warns = append(warns, f)
		}
	}

	switch {
	case len(blocks) > 0:
		return emitDecision(w, ev, "deny", join(blocks))
	case len(asks) > 0:
		return emitDecision(w, ev, "ask", join(asks))
	default:
		// warn ничего не останавливает: сообщение показывается, действие идёт.
		write(w, map[string]any{"systemMessage": "⚠ q0t-gates\n" + join(warns)})
		return 0
	}
}

func emitDecision(w io.Writer, ev rule.Event, decision, reason string) int {
	switch ev {
	case rule.Stop, rule.SubagentStop:
		// Stop не различает deny и ask: в обоих случаях сессия не закрывается и
		// решение остаётся за человеком, который читает reason.
		write(w, map[string]any{"decision": "block", "reason": reason})
		return 0

	case rule.UserPromptSubmit:
		if decision == "deny" {
			write(w, map[string]any{"decision": "block", "reason": reason})
			return 0
		}
		write(w, map[string]any{"systemMessage": reason})
		return 0

	default: // PreToolUse, PostToolUse
		write(w, map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            string(ev),
				"permissionDecision":       decision,
				"permissionDecisionReason": reason,
			},
			"systemMessage": "⛔ q0t-gates\n" + reason,
		})
		return 0
	}
}

func join(fs []Finding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, f.text())
	}
	return strings.Join(parts, "\n\n")
}

func write(w io.Writer, v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	w.Write(append(b, '\n'))
}
