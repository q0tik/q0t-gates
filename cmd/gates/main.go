// Команда gates — управление правилами и чтение журнала.
//
// Отдельный бинарь от gate: горячий путь хука не должен тащить в себя парсинг
// флагов, форматирование таблиц и чтение журнала.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/q0tik/q0t-gates/internal/audit"
	"github.com/q0tik/q0t-gates/internal/cascade"
	"github.com/q0tik/q0t-gates/internal/rule"
)

const usage = `gates — управление правилами q0t-gates

  gates list [dir]       действующие правила для директории (по умолчанию — текущая)
  gates library          что лежит на складе и где активировано
  gates enable <id> [dir]  активировать правило склада в проекте (симлинк)
  gates enable --global <id>
  gates disable <id> [dir] убрать симлинк правила из проекта
  gates check            распарсить все правила склада и активные наборы
  gates audit [месяц]    сводка журнала (например: gates audit 2026-08)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	root := repoRoot()
	var err error
	switch os.Args[1] {
	case "list":
		err = cmdList(root, arg(2, "."))
	case "library":
		err = cmdLibrary(root)
	case "enable":
		err = cmdEnable(root, os.Args[2:])
	case "disable":
		err = cmdDisable(root, os.Args[2:])
	case "check":
		err = cmdCheck(root)
	case "audit":
		err = cmdAudit(root, arg(2, time.Now().UTC().Format("2006-01")))
	default:
		fmt.Print(usage)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func arg(i int, def string) string {
	if len(os.Args) > i && !strings.HasPrefix(os.Args[i], "-") {
		return os.Args[i]
	}
	return def
}

func cmdList(root, dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	globalDir := filepath.Join(root, "global")

	events := []rule.Event{rule.PreToolUse, rule.PostToolUse, rule.UserPromptSubmit, rule.Stop, rule.SubagentStop}
	total := 0
	for _, ev := range events {
		rules, errs := cascade.Collect(globalDir, abs, home, ev)
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "  ⚠ ", e)
		}
		if len(rules) == 0 {
			continue
		}
		fmt.Printf("\n%s\n", ev)
		for _, r := range rules {
			fmt.Printf("  %-8s %-28s %s\n", badge(r.Severity), r.ID, shorten(r.Description, 70))
			fmt.Printf("           %s\n", relHome(r.Path, home))
			total++
		}
	}
	if total == 0 {
		fmt.Printf("Для %s правил нет.\n", relHome(abs, home))
	}
	return nil
}

func badge(s rule.Severity) string {
	switch s {
	case rule.Block:
		return "⛔block"
	case rule.Ask:
		return "❓ask"
	default:
		return "⚠warn"
	}
}

func cmdLibrary(root string) error {
	var expired []*rule.Rule
	libDir := filepath.Join(root, "library")
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return err
	}
	globalDir := filepath.Join(root, "global")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".toml")
		mark := " "
		if _, err := os.Lstat(filepath.Join(globalDir, e.Name())); err == nil {
			mark = "G"
		}
		r, err := rule.Load(filepath.Join(libDir, e.Name()))
		if err != nil {
			fmt.Printf("  ✗ %-28s БИТОЕ: %v\n", id, err)
			continue
		}
		age := ""
		if r.Expired(time.Now()) {
			age = "  ⏰ПОРА ПЕРЕСМОТРЕТЬ (" + r.ReviewAfter + ")"
		} else if r.ReviewAfter == "" {
			age = "  ∞"
		}
		fmt.Printf("%s %-8s %-28s %s%s\n", mark, badge(r.Severity), id, shorten(r.Description, 52), age)
		expired = append(expired, r)
	}
	fmt.Println("\nG — активировано глобально. Для проектов: gates list <dir>")

	// Правило, у которого нет даты пересмотра, живёт вечно — в том числе после
	// того, как причина его появления исчезла. Это главный способ, которым свод
	// правил превращается в свалку.
	var forever int
	for _, r := range expired {
		if r.ReviewAfter == "" {
			forever++
		}
	}
	if forever > 0 {
		fmt.Printf("∞ — без даты пересмотра: %d. Правило без review_after никто не удалит,\n"+
			"    даже когда причина ушла. Проставь дату там, где правило временное.\n", forever)
	}
	return nil
}

func cmdEnable(root string, args []string) error {
	global := false
	var rest []string
	for _, a := range args {
		if a == "--global" {
			global = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) == 0 {
		return fmt.Errorf("нужен id правила")
	}
	id := strings.TrimSuffix(rest[0], ".toml")
	src := filepath.Join(root, "library", id+".toml")
	if _, err := rule.Load(src); err != nil {
		return fmt.Errorf("правило не загружается, активировать нельзя: %w", err)
	}

	var dstDir string
	if global {
		dstDir = filepath.Join(root, "global")
	} else {
		base := "."
		if len(rest) > 1 {
			base = rest[1]
		}
		abs, err := filepath.Abs(base)
		if err != nil {
			return err
		}
		dstDir = filepath.Join(abs, cascade.GatesDir)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dstDir, id+".toml")
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s уже активировано", dst)
	}
	if err := os.Symlink(src, dst); err != nil {
		return err
	}
	fmt.Printf("✅ %s → %s\n", id, dst)
	return nil
}

func cmdDisable(root string, args []string) error {
	global := false
	var rest []string
	for _, a := range args {
		if a == "--global" {
			global = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) == 0 {
		return fmt.Errorf("нужен id правила")
	}
	id := strings.TrimSuffix(rest[0], ".toml")

	var dstDir string
	if global {
		dstDir = filepath.Join(root, "global")
	} else {
		base := "."
		if len(rest) > 1 {
			base = rest[1]
		}
		abs, err := filepath.Abs(base)
		if err != nil {
			return err
		}
		dstDir = filepath.Join(abs, cascade.GatesDir)
	}
	dst := filepath.Join(dstDir, id+".toml")
	fi, err := os.Lstat(dst)
	if err != nil {
		return fmt.Errorf("%s не активировано", id)
	}
	// Снимаем только симлинки: собственный файл правила проекта удалять молча
	// нельзя — это чужая работа, а не наша ссылка.
	if fi.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s — не симлинк, а файл правила проекта; удали вручную, если правда нужно", dst)
	}
	if err := os.Remove(dst); err != nil {
		return err
	}
	fmt.Printf("✅ снято: %s\n", dst)
	return nil
}

// cmdCheck — то, что должно висеть в CI и прогоняться перед активацией правила.
func cmdCheck(root string) error {
	bad := 0
	seen := map[string]bool{}
	for _, dir := range []string{"library", "global"} {
		full := filepath.Join(root, dir)
		entries, err := os.ReadDir(full)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".toml") {
				continue
			}
			p := filepath.Join(full, e.Name())
			if seen[e.Name()] && dir == "global" {
				continue // симлинк на уже проверенное правило склада
			}
			seen[e.Name()] = true
			if _, err := rule.Load(p); err != nil {
				fmt.Printf("✗ %v\n", err)
				bad++
			}
		}
	}
	if bad > 0 {
		return fmt.Errorf("битых правил: %d", bad)
	}
	fmt.Println("✅ все правила загружаются")
	return checkTimeouts()
}

// checkTimeouts — согласован ли таймаут хука с тем, сколько правило реально ждёт.
//
// Рассогласование не видно ничем: гейт отправляет подтверждение, человек его
// нажимает, но процесс уже убит по таймауту хука — и команда молча отклоняется.
// Ровно это случилось на homelab: ожидание 480с при таймауте хука 60с.
func checkTimeouts() error {
	home, _ := os.UserHomeDir()
	raw, err := os.ReadFile(filepath.Join(home, ".claude/settings.json"))
	if err != nil {
		return nil // движок может быть не установлен — это не ошибка правил
	}
	var cfg struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return nil
	}

	hookTimeout := map[string]int{}
	for ev, groups := range cfg.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if strings.Contains(h.Command, "q0t-gates") {
					hookTimeout[ev] = h.Timeout
				}
			}
		}
	}
	if len(hookTimeout) == 0 {
		return nil
	}

	// Сколько правило может ждать: подтверждение человека берёт срок из конфига
	// Telegram, judge — из своего поля timeout.
	wait := 0
	if b, err := os.ReadFile(filepath.Join(home, ".claude/dbhub-telegram.env")); err == nil {
		if m := reApprovalTimeout.FindSubmatch(b); m != nil {
			fmt.Sscanf(string(m[1]), "%d", &wait)
		} else {
			wait = 540 // дефолт скрипта подтверждения
		}
	}

	var problems []string
	if wait > 0 {
		if t := hookTimeout["PreToolUse"]; t > 0 && wait+60 > t {
			problems = append(problems, fmt.Sprintf(
				"PreToolUse: хук живёт %dс, а подтверждение ждёт %dс — нажатие придёт уже некому.\n"+
					"   Нужно: таймаут хука ≥ %dс либо DBHUB_APPROVAL_TIMEOUT ≤ %dс",
				t, wait, wait+60, t-60))
		}
	}

	if len(problems) > 0 {
		fmt.Println("\n⚠ таймауты рассогласованы:")
		for _, p := range problems {
			fmt.Println("   " + p)
		}
		return fmt.Errorf("рассогласование таймаутов: %d", len(problems))
	}
	fmt.Println("✅ таймауты согласованы")
	return nil
}

var reApprovalTimeout = regexp.MustCompile(`DBHUB_APPROVAL_TIMEOUT\s*=\s*"?(\d+)`)

// cmdAudit — менеджерский взгляд: какие гейты срабатывают, какие обходят.
//
// Гейт с большой долей обходов не дисциплинирует, а мешает: его надо чинить,
// а не ужесточать.
func cmdAudit(root, month string) error {
	path := filepath.Join(root, "audit", month+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("журнала за %s нет (%s)", month, path)
	}
	defer f.Close()

	type stat struct{ violated, escaped, byAgent, failed, errored int }
	stats := map[string]*stat{}
	var errLines []string

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		key := r.Rule
		if key == "" {
			key = "(движок)"
		}
		s := stats[key]
		if s == nil {
			s = &stat{}
			stats[key] = s
		}
		switch r.Verdict {
		case audit.Violated:
			s.violated++
		case audit.Escaped:
			s.escaped++
		case audit.EscapedByAgent:
			s.byAgent++
		case audit.JudgeFailed:
			s.failed++
		case audit.Error:
			s.errored++
			if len(errLines) < 5 {
				errLines = append(errLines, shorten(r.Reason, 110))
			}
		}
	}

	ids := make([]string, 0, len(stats))
	for k := range stats {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := stats[ids[i]], stats[ids[j]]
		return a.violated+a.escaped+a.byAgent > b.violated+b.escaped+b.byAgent
	})

	fmt.Printf("Журнал за %s\n\n", month)
	fmt.Printf("%-30s %9s %8s %14s %8s\n", "правило", "сработал", "обошли", "обошёл агент", "ошибки")
	for _, id := range ids {
		s := stats[id]
		fmt.Printf("%-30s %9d %8d %14d %8d\n", shorten(id, 30), s.violated, s.escaped, s.byAgent, s.failed+s.errored)
	}
	if len(errLines) > 0 {
		fmt.Println("\nПоследние ошибки движка:")
		for _, l := range errLines {
			fmt.Println("  ·", l)
		}
	}
	fmt.Println("\nВысокая доля обходов = кривой гейт, а не недисциплинированность.")
	fmt.Println("«обошёл агент» — маркер вписан без санкции в твоём сообщении: смотреть отдельно.")
	return nil
}

func shorten(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func relHome(p, home string) string {
	if home != "" && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

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
