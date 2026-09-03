package tests

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Правило блокирует выполнение и требует живого Telegram, поэтому e2e через
// движок был бы фикцией. Проверяем классификатор напрямую: главное здесь —
// не ложные срабатывания на обычной работе, иначе подтверждать придётся каждый
// второй вызов и механизм отключат.
func classify(t *testing.T, cmd string) (violated bool, reason string) {
	t.Helper()
	script, err := filepath.Abs("../checks/confirm_destructive.py")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"sources": map[string]string{"command": cmd}})

	c := exec.Command("python3", script)
	c.Stdin = bytes.NewReader(payload)
	// Конфига нет: до Telegram дело не дойдёт, но опасную команду скрипт обязан
	// распознать и — по fail-closed — отклонить.
	c.Env = append(c.Environ(), "DBHUB_APPROVAL_ENV=/nonexistent")
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Run(); err != nil {
		t.Fatalf("скрипт упал: %v (%s)", err, out.String())
	}
	var v struct {
		Violated bool   `json:"violated"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &v); err != nil {
		t.Fatalf("непарсимый вердикт: %s", out.String())
	}
	return v.Violated, v.Reason
}

func TestDestructiveAsksForConfirmation(t *testing.T) {
	dangerous := []string{
		"docker compose down",
		"docker compose -f ~/Services/docker-compose.yml down",
		"docker volume rm services_vaultwarden",
		"systemctl stop adguard",
		"rm -rf ~/obsidian-vault",
		"rm -rf /var/lib/docker/volumes/x",
		`psql -h localhost -c "DROP TABLE users"`,
		"redis-cli FLUSHALL",
		"alembic downgrade -1",
		"docker system prune -af",
	}
	for _, cmd := range dangerous {
		t.Run(cmd, func(t *testing.T) {
			if v, r := classify(t, cmd); !v {
				t.Errorf("должно требовать подтверждения, но пропущено: %s", r)
			}
		})
	}
}

// Ложное срабатывание здесь дороже пропуска: механизм, который спрашивает на
// каждый второй вызов, выключат целиком.
func TestOrdinaryWorkPassesSilently(t *testing.T) {
	safe := []string{
		"docker ps",
		"docker logs -f nginx",
		"docker compose up -d",
		"ls -la ~/Services",
		"git status",
		"git diff --staged",
		"rm -rf node_modules",
		"rm -rf /tmp/build-cache",
		"npm install",
		"go test ./...",
		`psql -c "SELECT count(*) FROM users"`,
		"grep -r 'docker compose down' docs/",
		"cat ~/Services/docker-compose.yml",
	}
	for _, cmd := range safe {
		t.Run(cmd, func(t *testing.T) {
			if v, r := classify(t, cmd); v {
				t.Errorf("обычная работа не должна требовать подтверждения, получили: %s", r)
			}
		})
	}
}

// Мусор на входе — операция не состоится: для разрушительных команд «не понял,
// пропускаю» неприемлемо.
func TestGarbageInputFailsClosed(t *testing.T) {
	script, _ := filepath.Abs("../checks/confirm_destructive.py")
	c := exec.Command("python3", script)
	c.Stdin = strings.NewReader("не json")
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Run(); err != nil {
		t.Fatalf("скрипт обязан выйти нулём: %v", err)
	}
	var v struct {
		Violated bool `json:"violated"`
	}
	json.Unmarshal(bytes.TrimSpace(out.Bytes()), &v)
	if !v.Violated {
		t.Error("мусорный вход должен блокировать, а не пропускать")
	}
}
