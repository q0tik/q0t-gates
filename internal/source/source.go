// Package source вычисляет источники — абстракции над тем, откуда берутся данные
// для проверки.
//
// Правило описывает, ЧТО проверяем, а не КАК достаём: сообщение коммита одинаково
// извлекается из `git commit -m` и из аргументов MCP-инструмента. Без этого каждое
// правило пришлось бы дублировать под каждый способ вызова.
package source

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/q0tik/q0t-gates/internal/event"
)

// Resolver вычисляет источники лениво и кэширует результат: staged_diff не должен
// запускать git, если ни одно правило его не просит.
type Resolver struct {
	ev    *event.Event
	cache map[string]string
	tr    *transcript // разобранный транскрипт, тоже лениво
}

func New(ev *event.Event) *Resolver {
	return &Resolver{ev: ev, cache: map[string]string{}}
}

// Get возвращает значение источника. Неизвестный источник даёт пустую строку:
// имена валидируются на загрузке правила, а на горячем пути движок не должен
// падать из-за опечатки.
func (r *Resolver) Get(name string) string {
	if v, ok := r.cache[name]; ok {
		return v
	}
	v := r.compute(name)
	r.cache[name] = v
	return v
}

func (r *Resolver) compute(name string) string {
	switch {
	case name == "command":
		return r.ev.ToolInputField("command")

	case name == "tool_input":
		return string(r.ev.ToolInput)

	case name == "prompt":
		return r.ev.Prompt

	case name == "staged_diff":
		return r.git("diff", "--staged")

	case name == "git_remote":
		// Принадлежность репозитория определяется фактом, а не расположением в
		// дереве: рабочий репозиторий может лежать где угодно, и требовать от
		// модели вывода «этот каталог — рабочий» значит вернуть ту самую
		// ненадёжную композицию фактов, ради устранения которой движок и написан.
		return strings.TrimSpace(r.git("remote", "-v"))

	case name == "git_branch":
		return strings.TrimSpace(r.git("rev-parse", "--abbrev-ref", "HEAD"))

	case name == "commit_message":
		return r.commitMessage()

	case name == "transcript":
		return r.transcript().mainText

	case name == "transcript.user":
		// Только реплики человека. Сигнал о том, ЧТО происходит, нельзя брать из
		// полного транскрипта: туда попадают тексты загруженных скиллов, прочитанные
		// заметки и выдача поиска. Слово вроде «инцидент» встречается там почти
		// всегда — на реальных сессиях это давало 18 срабатываний из 25.
		return r.transcript().userText

	case name == "transcript.all":
		return r.transcript().allText

	case name == "transcript.tools":
		return strings.Join(r.transcript().mainTools, "\n")

	case name == "transcript.tools.all":
		return strings.Join(r.transcript().allTools, "\n")

	// Источника in_subagent больше нет. Проверено экспериментом 2026-08-30:
	// вызов инструмента из субагента приходит хуку с ТЕМ ЖЕ session_id и тем же
	// transcript_path, что и вызов из основного контекста, а поля isSidechain в
	// событии нет вовсе. Отличить одно от другого по данным события нельзя,
	// поэтому правила вида «только через субагента» гейтом не выражаются.

	case strings.HasPrefix(name, "file:"):
		p := strings.TrimPrefix(name, "file:")
		if !filepath.IsAbs(p) {
			p = filepath.Join(r.ev.CWD, p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return string(b)
	}
	return ""
}

func (r *Resolver) git(args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.ev.CWD
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// commitMessageArgs — поля MCP-инструментов, в которых лежит сообщение коммита.
// Список расширяется по мере появления новых серверов; пока поле неизвестно,
// правило про коммиты через этот сервер не сработает — поэтому список важно
// держать актуальным.
var commitMessageArgs = []string{"commit_message", "message", "commitMessage"}

var reCommitDashM = regexp.MustCompile(`(?s)-m\s+('([^']*)'|"((?:[^"\\]|\\.)*)"|(\S+))`)

// commitMessage достаёт сообщение коммита из Bash-команды или из аргументов MCP.
func (r *Resolver) commitMessage() string {
	if cmd := r.ev.ToolInputField("command"); cmd != "" {
		var parts []string
		for _, m := range reCommitDashM.FindAllStringSubmatch(cmd, -1) {
			switch {
			case m[2] != "":
				parts = append(parts, m[2])
			case m[3] != "":
				parts = append(parts, strings.ReplaceAll(m[3], `\"`, `"`))
			case m[4] != "":
				parts = append(parts, m[4])
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n\n")
		}
		// Коммит без -m: сообщение придёт из редактора или из файла, движок его
		// не видит. Пустая строка честнее выдумки.
		return ""
	}
	for _, key := range commitMessageArgs {
		if v := r.ev.ToolInputField(key); v != "" {
			return v
		}
	}
	return ""
}

type transcript struct {
	mainText        string
	userText        string
	allText         string
	mainTools       []string
	allTools        []string
	lastIsSidechain bool
}

// transcript разбирает JSONL-транскрипт сессии.
//
// Записи субагентов помечены isSidechain = true. Это единственный способ отличить
// вызов из основного контекста от вызова внутри субагента — на нём держатся
// правила вида «тяжёлые чтения только через субагента».
func (r *Resolver) transcript() *transcript {
	if r.tr != nil {
		return r.tr
	}
	t := &transcript{}
	r.tr = t

	f, err := os.Open(r.ev.TranscriptPath)
	if err != nil {
		return t
	}
	defer f.Close()

	var mainB, allB, userB strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20) // строки транскрипта бывают очень длинными

	for sc.Scan() {
		var rec struct {
			Type        string `json:"type"`
			IsSidechain bool   `json:"isSidechain"`
			Message     struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Message.Content == nil {
			continue
		}
		t.lastIsSidechain = rec.IsSidechain

		text, tools := extractContent(rec.Message.Content)
		allB.WriteString(text)
		allB.WriteByte('\n')
		t.allTools = append(t.allTools, tools...)
		if !rec.IsSidechain {
			mainB.WriteString(text)
			mainB.WriteByte('\n')
			t.mainTools = append(t.mainTools, tools...)

			// Результаты инструментов приходят тоже как user-записи, но человек их
			// не писал — берём только текстовые блоки.
			if rec.Type == "user" || rec.Message.Role == "user" {
				userB.WriteString(plainText(rec.Message.Content))
				userB.WriteByte('\n')
			}
		}
	}
	t.mainText = mainB.String()
	t.userText = userB.String()
	t.allText = allB.String()
	return t
}

// Харнесс подмешивает в user-сообщения контент, которого человек не писал:
// тексты загруженных скиллов, CLAUDE.md и напоминания внутри <system-reminder>,
// раскрытые слэш-команды. Для «что сказал человек» это шум, причём решающий:
// слово «инцидент» есть в самом скилле qb-vault, и без фильтра правило
// срабатывало на 16 сессиях из 25.
var reSystemReminder = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

var injectedPrefixes = []string{
	"Base directory for this skill:",
	"<command-name>",
	"<local-command",
	"<command-message>",
	"---\nname:",
}

func isInjected(t string) bool {
	t = strings.TrimSpace(t)
	for _, p := range injectedPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// plainText берёт из сообщения только текст, написанный человеком: строку целиком
// либо text-блоки, за вычетом подмешанного харнессом. tool_result и tool_use сюда
// не попадают.
func plainText(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return humanPart(s)
	}
	var blocks []map[string]any
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var b strings.Builder
	for _, blk := range blocks {
		if blk["type"] != "text" {
			continue
		}
		if t, ok := blk["text"].(string); ok {
			if h := humanPart(t); h != "" {
				b.WriteString(h)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func humanPart(t string) string {
	if isInjected(t) {
		return ""
	}
	return strings.TrimSpace(reSystemReminder.ReplaceAllString(t, ""))
}

// extractContent вытаскивает из блоков сообщения текст и имена вызванных
// инструментов. Для Skill имя дополняется аргументом — правила ссылаются на
// конкретный скилл, а не на факт вызова Skill вообще.
func extractContent(raw json.RawMessage) (string, []string) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}

	var blocks []map[string]any
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", nil
	}

	var b strings.Builder
	var tools []string
	for _, blk := range blocks {
		switch blk["type"] {
		case "text":
			if t, ok := blk["text"].(string); ok {
				b.WriteString(t)
				b.WriteByte('\n')
			}
		case "tool_use":
			name, _ := blk["name"].(string)
			if name == "" {
				continue
			}
			if name == "Skill" {
				if in, ok := blk["input"].(map[string]any); ok {
					if sk, ok := in["skill"].(string); ok {
						name = "Skill(" + sk + ")"
					}
				}
			}
			tools = append(tools, name)
			if in, err := json.Marshal(blk["input"]); err == nil {
				b.WriteString(name)
				b.WriteByte(' ')
				b.Write(in)
				b.WriteByte('\n')
			}
		case "tool_result":
			if c, ok := blk["content"].(string); ok {
				b.WriteString(c)
				b.WriteByte('\n')
			}
		}
	}
	return b.String(), tools
}
