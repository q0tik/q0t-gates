#!/usr/bin/env bash
# Регистрирует движок в ~/.claude/settings.json.
#
# Одна регистрация на все события: активность правил определяется наличием
# файлов, а не настройками, поэтому переустанавливать при добавлении правил
# не нужно.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETTINGS="$HOME/.claude/settings.json"
GATE="$ROOT/bin/gate"

[[ -x "$GATE" ]] || { echo "нет бинаря $GATE — сначала make build" >&2; exit 1; }
[[ -f "$SETTINGS" ]] || { echo "нет $SETTINGS" >&2; exit 1; }

BACKUP="$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
cp "$SETTINGS" "$BACKUP"
echo "бэкап: $BACKUP"

python3 - "$SETTINGS" "$GATE" <<'PY'
import json, sys

settings_path, gate = sys.argv[1], sys.argv[2]
with open(settings_path) as f:
    cfg = json.load(f)

# Таймаут хука обязан пережить самое долгое, что правило может делать.
# Рассогласование стоило живого бага: гейт слал подтверждение в Telegram и
# ждал 480с, а Claude Code убивал его через 60 — нажатие приходило уже
# некому, команда молча отклонялась.
EVENT_TIMEOUT = {
    "PreToolUse": 600,      # тут правило может ждать нажатия человека
    "Stop": 180,            # тут работает judge (claude -p, до 45с)
    "SubagentStop": 180,
    "PostToolUse": 60,
    "UserPromptSubmit": 60,
}
EVENTS = list(EVENT_TIMEOUT)
hooks = cfg.setdefault("hooks", {})

added, kept = [], []
for ev in EVENTS:
    groups = hooks.setdefault(ev, [])

    # Идемпотентность: если движок уже зарегистрирован на событие — только
    # обновляем путь к бинарю, ничего не дублируя.
    found = False
    for g in groups:
        for h in g.get("hooks", []):
            if "q0t-gates" in h.get("command", ""):
                h["command"] = gate
                h["timeout"] = EVENT_TIMEOUT[ev]
                found = True
    if found:
        kept.append(ev)
        continue

    groups.append({
        "hooks": [{
            "type": "command",
            "command": gate,
            "timeout": EVENT_TIMEOUT[ev],
            "statusMessage": "q0t-gates: проверка правил...",
        }]
    })
    added.append(ev)

with open(settings_path, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")

if added:
    print("зарегистрировано:", ", ".join(added))
if kept:
    print("обновлены путь и таймаут:", ", ".join(kept))
print("таймауты:", ", ".join(f"{e}={t}с" for e, t in EVENT_TIMEOUT.items()))
PY

python3 -c "import json;json.load(open('$SETTINGS'))" \
  || { echo "settings.json сломан — откатываю"; cp "$BACKUP" "$SETTINGS"; exit 1; }

echo "✅ движок подключён"
echo
echo "Дальше:"
echo "  gates library                          что есть на складе"
echo "  gates enable --global no-secrets-staged"
echo "  gates list ~/Developer/QB              что действует в проекте"
