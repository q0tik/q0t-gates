// Package cascade собирает действующий набор правил по дереву директорий.
//
// Хуки Claude Code не каскадируются: они читаются из ~/.claude/settings.json и
// из настроек корня сессии, а вложенные .claude/ никто не подхватывает. Поэтому
// наследование, которого ждёшь по аналогии с CLAUDE.md, реализовано здесь.
package cascade

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/q0tik/q0t-gates/internal/rule"
)

// GatesDir — имя директории с правилами внутри проекта.
const GatesDir = ".claude/gates"

// Collect возвращает действующие правила для события, собранные от глобального
// набора вниз до start.
//
// Правило с тем же id ниже по дереву перекрывает верхнее — так подпроект может
// ослабить severity или выключить унаследованное правило через disabled = true.
// Правила с disabled в результат не попадают.
func Collect(globalDir, start, home string, ev rule.Event) ([]*rule.Rule, []error) {
	var errs []error
	byID := map[string]*rule.Rule{}

	// Порядок обхода: сначала глобальный набор, затем директории от $HOME вниз
	// к start — так что чем ближе к файлу, тем позже перезапись, тем выше приоритет.
	for _, dir := range append([]string{globalDir}, chain(start, home)...) {
		rules, e := loadDir(dir)
		errs = append(errs, e...)
		for _, r := range rules {
			byID[r.ID] = r
		}
	}

	out := make([]*rule.Rule, 0, len(byID))
	for _, r := range byID {
		if r.Disabled || r.Event != ev {
			continue
		}
		out = append(out, r)
	}
	// Детерминированный порядок: иначе вердикт зависел бы от обхода карты, и
	// два одинаковых запуска могли бы дать разные сообщения.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, errs
}

// chain возвращает директории с правилами от home вниз к start включительно.
// Подъём выше $HOME не выполняется.
func chain(start, home string) []string {
	start, err := filepath.Abs(start)
	if err != nil {
		return nil
	}
	home = filepath.Clean(home)

	var dirs []string
	for d := start; ; d = filepath.Dir(d) {
		dirs = append(dirs, filepath.Join(d, GatesDir))
		if d == home || d == filepath.Dir(d) || !strings.HasPrefix(d, home) {
			break
		}
	}
	// Разворачиваем: от корня вниз.
	for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
		dirs[i], dirs[j] = dirs[j], dirs[i]
	}
	return dirs
}

func loadDir(dir string) ([]*rule.Rule, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil // директории нет — это норма, а не ошибка
	}
	var rules []*rule.Rule
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		r, err := rule.Load(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, r)
	}
	return rules, errs
}

// HasAnyGates — дешёвая проверка для быстрого пути: есть ли вообще хоть одна
// директория с правилами в цепочке. Только stat, без чтения файлов.
func HasAnyGates(globalDir, start, home string) bool {
	if hasFiles(globalDir) {
		return true
	}
	for _, d := range chain(start, home) {
		if hasFiles(d) {
			return true
		}
	}
	return false
}

func hasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".toml") {
			return true
		}
	}
	return false
}
