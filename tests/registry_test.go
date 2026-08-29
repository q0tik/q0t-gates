package tests

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Скрипт правила registry-covers-repos читает настоящее дерево ~/Developer/QB и
// настоящий реестр, поэтому e2e в изолированном окружении был бы фикцией.
// Проверяем его напрямую: важно, что он не срабатывает на пустом месте и
// молчит, когда репозиторий в сессии не упоминался.
func runRegistryCheck(t *testing.T, transcript string) map[string]any {
	t.Helper()
	script, err := filepath.Abs("../checks/registry_covers_repos.py")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"event":   map[string]any{"hook_event_name": "Stop"},
		"sources": map[string]string{"transcript": transcript},
	})

	cmd := exec.Command("python3", script)
	cmd.Stdin = bytes.NewReader(payload)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("скрипт упал: %v (%s)", err, out.String())
	}
	var v map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &v); err != nil {
		t.Fatalf("непарсимый вердикт: %s", out.String())
	}
	return v
}

func TestRegistryCheckSilentWhenRepoNotTouched(t *testing.T) {
	v := runRegistryCheck(t, "обсуждали погоду и ничего не трогали")
	if v["violated"] == true {
		t.Errorf("правило не должно срабатывать, когда репозиторий в сессии не упоминался: %v", v)
	}
}

func TestRegistryCheckHandlesGarbageInput(t *testing.T) {
	script, _ := filepath.Abs("../checks/registry_covers_repos.py")
	cmd := exec.Command("python3", script)
	cmd.Stdin = strings.NewReader("не json")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("на мусорном вводе скрипт обязан выйти нулём: %v", err)
	}
	var v map[string]any
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &v) != nil || v["violated"] == true {
		t.Errorf("мусорный ввод не должен давать срабатывание: %s", out.String())
	}
}
