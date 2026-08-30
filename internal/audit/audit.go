// Package audit пишет журнал срабатываний.
//
// Журнал — не отладочный лог, а источник данных: «какие гейты работают, а какие
// только мешают» должно быть метрикой, а не ощущением. Записи passed не пишутся —
// иначе журнал зарастёт отметкой о каждом вызове инструмента, а полезный сигнал
// (violated + escaped) в нём утонет.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Verdict string

const (
	Violated       Verdict = "violated"
	Escaped        Verdict = "escaped"
	EscapedByAgent Verdict = "escaped_by_agent"
	JudgeFailed    Verdict = "judge_failed"
	Error          Verdict = "error"
)

type Record struct {
	TS           string  `json:"ts"`
	Rule         string  `json:"rule"`
	Event        string  `json:"event"`
	Verdict      Verdict `json:"verdict"`
	Severity     string  `json:"severity"`
	CWD          string  `json:"cwd"`
	Session      string  `json:"session,omitempty"`
	Reason       string  `json:"reason,omitempty"`
	EscapeSource string  `json:"escape_source,omitempty"`
	RulePath     string  `json:"rule_path,omitempty"`
}

// Write добавляет запись в журнал текущего месяца.
//
// Ошибки записи глотаются намеренно: журнал не должен уметь заблокировать работу.
func Write(dir string, rec Record) {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	path := filepath.Join(dir, time.Now().UTC().Format("2006-01")+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
}
