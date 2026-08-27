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

EVENTS = ["PreToolUse", "PostToolUse", "Stop", "SubagentStop", "UserPromptSubmit"]
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
                found = True
    if found:
        kept.append(ev)
        continue

    groups.append({
        "hooks": [{
            "type": "command",
            "command": gate,
            "timeout": 60,
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
    print("обновлён путь:", ", ".join(kept))
PY

python3 -c "import json;json.load(open('$SETTINGS'))" \
  || { echo "settings.json сломан — откатываю"; cp "$BACKUP" "$SETTINGS"; exit 1; }

echo "✅ движок подключён"
echo
echo "Дальше:"
echo "  gates library                          что есть на складе"
echo "  gates enable --global no-secrets-staged"
echo "  gates list ~/Developer/QB              что действует в проекте"
