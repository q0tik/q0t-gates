// Package rule описывает схему правила и её загрузку из TOML.
//
// Один файл — одно правило. id правила = имя файла без расширения; внутри файла
// id не дублируется, чтобы имя и содержимое не могли разойтись.
package rule

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Severity — что движок делает при срабатывании правила.
type Severity string

const (
	Block Severity = "block" // действие не происходит / сессия не закрывается
	Ask   Severity = "ask"   // решает человек
	Warn  Severity = "warn"  // действие идёт, message уезжает агенту в контекст
)

// Type — способ проверки.
type Type string

const (
	Pattern Type = "pattern" // регексп по источнику
	Script  Type = "script"  // внешний скрипт, вердикт JSON на stdout
	Judge   Type = "judge"   // claude -p, вердикт JSON фиксированной формы
)

// Event — событие хука Claude Code.
type Event string

const (
	PreToolUse       Event = "PreToolUse"
	PostToolUse      Event = "PostToolUse"
	Stop             Event = "Stop"
	SubagentStop     Event = "SubagentStop"
	UserPromptSubmit Event = "UserPromptSubmit"
)

// Match — один блок [[match]]. Внутри блока условия соединяются по И.
//
// Ключ tool особый: имя инструмента, строка или список, с поддержкой glob.
// Все прочие ключи — имена источников, значения — регекспы.
type Match struct {
	Tool    []string
	Sources map[string]*regexp.Regexp
}

// Check — условие нарушения. Набор полей зависит от Type.
type Check struct {
	// pattern
	Source  string
	DenyIf  *regexp.Regexp
	Require *regexp.Regexp // require: нарушение, если НЕ нашлось

	// script
	Script string

	// judge
	Model   string
	Input   []string
	Prompt  string
	Timeout int // секунды
}

// Escape — легальный разовый обход с аудит-следом.
//
// Source ограничен источниками, которые пишет человек (см. AllowedEscapeSources):
// иначе агент выпишет себе амнистию сам и движок станет декорацией.
type Escape struct {
	Source string
	Marker string
}

// Rule — одно правило.
type Rule struct {
	ID          string
	Path        string // откуда загружено — для аудита и диагностики
	Description string
	Event       Event
	Type        Type
	Severity    Severity
	Message     string
	Match       []Match
	Check       Check
	Escape      *Escape
	Disabled    bool
	Reason      string // обязателен при Disabled
	FailClosed  bool
}

// AllowedEscapeSources — источники, в которых допустимо искать escape-маркер.
//
// prompt пишет только человек — подделка невозможна.
// commit_message допустим, но остаётся навсегда в истории git и помечается в
// аудите отдельно, если санкции пользователя в сессии не было.
var AllowedEscapeSources = map[string]bool{
	"prompt":         true,
	"commit_message": true,
}

// rawRule — промежуточная форма для TOML: регекспы приходят строками,
// tool бывает и строкой, и списком, [[match]] содержит произвольные ключи.
type rawRule struct {
	Description string           `toml:"description"`
	Event       string           `toml:"event"`
	Type        string           `toml:"type"`
	Severity    string           `toml:"severity"`
	Message     string           `toml:"message"`
	Disabled    bool             `toml:"disabled"`
	Reason      string           `toml:"reason"`
	FailClosed  bool             `toml:"fail_closed"`
	Match       []map[string]any `toml:"match"`
	Check       map[string]any   `toml:"check"`
	Escape      map[string]any   `toml:"escape"`
}

// Load читает правило из TOML-файла и валидирует его целиком.
//
// Валидация строгая и на загрузке, а не на срабатывании: правило с опечаткой
// должно ломаться на тесте, а не молча не срабатывать в проде полгода.
func Load(path string) (*Rule, error) {
	var raw rawRule
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, 0, len(u))
		for _, k := range u {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("%s: неизвестные поля: %s", path, strings.Join(keys, ", "))
	}

	id := strings.TrimSuffix(filepath.Base(path), ".toml")
	r := &Rule{
		ID:          id,
		Path:        path,
		Description: raw.Description,
		Event:       Event(raw.Event),
		Type:        Type(raw.Type),
		Severity:    Severity(raw.Severity),
		Message:     raw.Message,
		Disabled:    raw.Disabled,
		Reason:      raw.Reason,
		FailClosed:  raw.FailClosed,
	}

	// Выключающая заглушка: перекрывает унаследованное правило и больше ничего
	// не обязана содержать.
	if r.Disabled {
		if strings.TrimSpace(r.Reason) == "" {
			return nil, fmt.Errorf("%s: disabled = true требует reason", path)
		}
		return r, nil
	}

	if err := parseHeader(r, path); err != nil {
		return nil, err
	}
	if err := parseMatch(r, raw.Match, path); err != nil {
		return nil, err
	}
	if err := parseCheck(r, raw.Check, path); err != nil {
		return nil, err
	}
	if err := parseEscape(r, raw.Escape, path); err != nil {
		return nil, err
	}
	return r, nil
}

func parseHeader(r *Rule, path string) error {
	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("%s: description обязателен", path)
	}
	if strings.TrimSpace(r.Message) == "" {
		return fmt.Errorf("%s: message обязателен", path)
	}
	switch r.Event {
	case PreToolUse, PostToolUse, Stop, SubagentStop, UserPromptSubmit:
	default:
		return fmt.Errorf("%s: неизвестный event %q", path, r.Event)
	}
	switch r.Type {
	case Pattern, Script, Judge:
	default:
		return fmt.Errorf("%s: неизвестный type %q", path, r.Type)
	}
	switch r.Severity {
	case Block, Ask, Warn:
	default:
		return fmt.Errorf("%s: неизвестный severity %q", path, r.Severity)
	}
	return nil
}

func parseMatch(r *Rule, raw []map[string]any, path string) error {
	for i, blk := range raw {
		m := Match{Sources: map[string]*regexp.Regexp{}}
		for k, v := range blk {
			if k == "tool" {
				tools, err := asStringList(v)
				if err != nil {
					return fmt.Errorf("%s: match[%d].tool: %w", path, i, err)
				}
				m.Tool = tools
				continue
			}
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("%s: match[%d].%s: ожидалась строка-регексп", path, i, k)
			}
			re, err := regexp.Compile(s)
			if err != nil {
				return fmt.Errorf("%s: match[%d].%s: битый регексп: %w", path, i, k, err)
			}
			m.Sources[k] = re
		}
		r.Match = append(r.Match, m)
	}
	return nil
}

// checkKeys — допустимые ключи [check] для каждого типа. Проверяются явно:
// toml-декодер складывает [check] в map и лишние ключи не замечает, поэтому
// опечатка вроде timeoutt иначе тихо потеряла бы смысл правила.
var checkKeys = map[Type]map[string]bool{
	Pattern: {"source": true, "deny_if": true, "require": true},
	Script:  {"script": true},
	Judge:   {"prompt": true, "model": true, "timeout": true, "input": true},
}

func parseCheck(r *Rule, raw map[string]any, path string) error {
	if raw == nil {
		return fmt.Errorf("%s: [check] обязателен", path)
	}
	allowed := checkKeys[r.Type]
	var unknown []string
	for k := range raw {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%s: неизвестные поля в [check] для type = %q: %s",
			path, r.Type, strings.Join(unknown, ", "))
	}

	switch r.Type {
	case Pattern:
		src, _ := raw["source"].(string)
		if src == "" {
			return fmt.Errorf("%s: check.source обязателен для type = \"pattern\"", path)
		}
		r.Check.Source = src

		denyRaw, hasDeny := raw["deny_if"].(string)
		reqRaw, hasReq := raw["require"].(string)
		if hasDeny == hasReq {
			return fmt.Errorf("%s: ровно один из check.deny_if / check.require", path)
		}
		if hasDeny {
			re, err := regexp.Compile(denyRaw)
			if err != nil {
				return fmt.Errorf("%s: check.deny_if: битый регексп: %w", path, err)
			}
			r.Check.DenyIf = re
		} else {
			re, err := regexp.Compile(reqRaw)
			if err != nil {
				return fmt.Errorf("%s: check.require: битый регексп: %w", path, err)
			}
			r.Check.Require = re
		}

	case Script:
		s, _ := raw["script"].(string)
		if s == "" {
			return fmt.Errorf("%s: check.script обязателен для type = \"script\"", path)
		}
		r.Check.Script = s

	case Judge:
		p, _ := raw["prompt"].(string)
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("%s: check.prompt обязателен для type = \"judge\"", path)
		}
		r.Check.Prompt = p
		if m, ok := raw["model"].(string); ok {
			r.Check.Model = m
		} else {
			r.Check.Model = "haiku"
		}
		if t, ok := raw["timeout"].(int64); ok {
			r.Check.Timeout = int(t)
		} else {
			r.Check.Timeout = 30
		}
		if in, ok := raw["input"]; ok {
			list, err := asStringList(in)
			if err != nil {
				return fmt.Errorf("%s: check.input: %w", path, err)
			}
			r.Check.Input = list
		} else {
			r.Check.Input = []string{"transcript"}
		}
	}
	return nil
}

func parseEscape(r *Rule, raw map[string]any, path string) error {
	if raw == nil {
		return nil
	}
	src, _ := raw["source"].(string)
	marker, _ := raw["marker"].(string)
	if src == "" || marker == "" {
		return fmt.Errorf("%s: [escape] требует source и marker", path)
	}
	if !AllowedEscapeSources[src] {
		return fmt.Errorf(
			"%s: escape.source = %q запрещён; допустимы только источники, которые пишет человек: prompt, commit_message",
			path, src)
	}
	r.Escape = &Escape{Source: src, Marker: marker}
	return nil
}

func asStringList(v any) ([]string, error) {
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("ожидалась строка, получено %T", e)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("ожидалась строка или список строк, получено %T", v)
	}
}
