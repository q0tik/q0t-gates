#!/usr/bin/env python3
"""Разрушительная операция — спросить человека в Telegram и дождаться нажатия.

Зачем скриптом, а не обычным правилом: гейт умеет только «нарушено / не нарушено»,
а здесь решение принимает человек. Скрипт блокирует выполнение, шлёт команду в
Telegram с кнопками и возвращает `violated: false` только после явного «Выполнить».

Fail-closed по построению: нет сети, нет конфига, таймаут, чужой ответ, любая
ошибка — `violated: true`, то есть операция не состоится. Для команд, которые
гасят DNS всего дома или стирают данные без бэкапа, «не понял — пропускаю»
неприемлемо.

Вход  (stdin):  {"event": ..., "sources": {"command": "..."}}
Выход (stdout): {"violated": bool, "reason": "..."}

Конфиг (вне git, режим 600): ~/.claude/dbhub-telegram.env
  DBHUB_APPROVAL_BOT_TOKEN=...
  DBHUB_APPROVAL_CHAT_ID=...
  DBHUB_APPROVAL_TIMEOUT=540
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOME = os.path.expanduser("~")
CONFIG = os.environ.get("DBHUB_APPROVAL_ENV", os.path.join(HOME, ".claude/dbhub-telegram.env"))

# Пути, потеря которых невосстановима без бэкапа.
PROTECTED = [
    r"~/Services", r"~/srv", r"~/obsidian-vault", r"~/infra", r"~/backups",
    r"/var/lib/docker", r"~/\.claude", r"~/\.ssh", r"actions-runner",
]

# (регексп, как называть операцию человеку)
DANGER = [
    # контейнеры и сервисы: гасят работающее
    # Между `docker compose` и подкомандой обычно стоят флаги (-f, --profile),
    # поэтому «сразу после» проверять нельзя: docker compose -f x.yml down —
    # самая ходовая форма вызова.
    (r"\bdocker\s+compose\b[^|;&]*?\b(down|rm|kill|stop)\b", "остановка/удаление контейнеров"),
    (r"\bdocker\s+(rm|kill|stop)\b", "остановка/удаление контейнеров"),
    (r"\bdocker\s+volume\s+(rm|prune)\b", "удаление docker-томов"),
    (r"\bdocker\s+system\s+prune\b", "docker system prune"),
    (r"\bsystemctl\s+(stop|disable|mask)\b", "остановка/отключение systemd-юнита"),

    # данные
    (r"\brm\s+(-\w*\s+)*-\w*[rf]\w*\s", "рекурсивное удаление файлов"),
    (r"\b(mkfs|dd\s+if=|shred)\b", "операция уровня диска"),
    (r">\s*/dev/sd", "запись в блочное устройство"),

    # секреты и конфиги
    (r"(^|\s)(rm|mv|truncate|tee)\s+[^|]*\.env\b", "изменение файла с секретами"),
    (r"AdGuardHome\.yaml", "правка конфигурации AdGuard (DNS всего дома)"),

    # базы
    (r"\bpsql\b[^|]*\b(-c|--command)\b[^|]*\b(DROP|TRUNCATE|DELETE|ALTER|INSERT|UPDATE)\b", "разрушающий SQL"),
    # Запись через хранимку ключевыми словами не ловится: в
    # `SELECT modify_janus_settings('INSERT', ...)` слово INSERT лежит внутри
    # литерала. Ловим по имени функции — оно вне кавычек.
    (r"\b(modify|insert|update|delete|upsert|merge|claim|cleanup|remove|write|save|apply|recalc|set|add)_[a-z0-9_]*\s*\(", "запись через хранимку"),
    (r"\bcall_pg_proc\s*\(", "запись через хранимку (call_pg_proc)"),
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b", "разрушающий SQL"),
    (r"\bredis-cli\b[^|]*\b(FLUSHALL|FLUSHDB)\b", "очистка Redis"),
    (r"\bkafka-topics(\.sh)?\b[^|]*--delete\b", "удаление Kafka-топика"),
    (r"\balembic\s+downgrade\b", "откат миграции"),
]

# Чтение и разведка деструктивными не считаются, даже если слова совпали.
SAFE_PREFIX = re.compile(r"^\s*(git\s+(status|diff|log|show)|ls|cat|grep|rg|find|docker\s+(ps|logs|images|inspect))\b")

# Служебные функции Postgres с теми же префиксами — не запись в наши таблицы.
PROC_SAFE = re.compile(r"\b(set_config|set_bit|set_byte|set_masklen|add_month)\s*\(", re.I)


def verdict(violated: bool, reason: str) -> None:
    print(json.dumps({"violated": violated, "reason": reason}, ensure_ascii=False))
    sys.exit(0)


def read_config() -> dict[str, str]:
    cfg: dict[str, str] = {}
    try:
        with open(CONFIG, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip().removeprefix("export ").strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return cfg


def api(token: str, method: str, payload: dict | None = None, timeout: int = 20):
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def classify(cmd: str) -> str:
    if SAFE_PREFIX.match(cmd):
        return ""
    probe = PROC_SAFE.sub("", cmd)  # служебные функции не должны давать срабатывание
    hits = [name for rx, name in DANGER if re.search(rx, probe, re.I)]
    if not hits:
        return ""
    # Удаление вне защищённых путей — обычная работа, спрашивать незачем.
    if hits == ["рекурсивное удаление файлов"] and not any(
        re.search(p.replace("~", re.escape(HOME) + "|~"), cmd) for p in PROTECTED
    ):
        return ""
    return ", ".join(dict.fromkeys(hits))


def ask_telegram(token: str, chat: str, host: str, cmd: str, what: str, wait: int) -> tuple[bool, str]:
    """Возвращает (подтверждено, причина). Любая неопределённость — False."""
    nonce = secrets.token_hex(6)
    text = (
        f"🛑 <b>{what}</b>\n"
        f"на <code>{host}</code>\n\n"
        f"<pre>{cmd[:3000]}</pre>\n"
        f"Выполнить?"
    )
    keyboard = {"inline_keyboard": [[
        {"text": "✅ Выполнить", "callback_data": f"ok:{nonce}"},
        {"text": "🛑 Отклонить", "callback_data": f"no:{nonce}"},
    ]]}

    try:
        sent = api(token, "sendMessage", {
            "chat_id": chat, "text": text, "parse_mode": "HTML", "reply_markup": keyboard,
        })
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
        return False, f"Telegram недоступен: {type(e).__name__}"
    if not sent.get("ok"):
        return False, f"Telegram отказал: {str(sent.get('description'))[:120]}"

    msg_id = sent["result"]["message_id"]
    deadline = time.time() + wait

    # КОРОТКИЕ опросы без сдвига offset. Длинный поллинг с одним токеном на двух
    # машинах приводит к «terminated by other getUpdates request», а сдвиг offset
    # съел бы чужое нажатие: очередь общая. Здесь каждый берёт только своё по
    # nonce, чужие апдейты остаются в очереди для второй машины.
    while time.time() < deadline:
        try:
            upd = api(token, "getUpdates", {"timeout": 0, "limit": 50, "offset": -50}, timeout=15)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
            time.sleep(3)
            continue
        for u in upd.get("result", []):
            cq = u.get("callback_query")
            if not cq:
                continue
            data = cq.get("data", "")
            if not data.endswith(nonce):
                continue  # чужой запрос — не трогаем, пусть заберёт другая машина
            try:
                api(token, "answerCallbackQuery", {"callback_query_id": cq["id"]}, timeout=10)
            except Exception:  # noqa: BLE001 — не критично для решения
                pass
            approved = data.startswith("ok:")
            mark = "✅ выполняется" if approved else "🛑 отклонено"
            try:
                api(token, "editMessageText", {
                    "chat_id": chat, "message_id": msg_id, "parse_mode": "HTML",
                    "text": text + f"\n\n<b>{mark}</b>",
                }, timeout=10)
            except Exception:  # noqa: BLE001
                pass
            return approved, ("подтверждено в Telegram" if approved else "отклонено в Telegram")
        time.sleep(3)

    try:
        api(token, "editMessageText", {
            "chat_id": chat, "message_id": msg_id, "parse_mode": "HTML",
            "text": text + "\n\n<b>⏰ истекло время — отклонено</b>",
        }, timeout=10)
    except Exception:  # noqa: BLE001
        pass
    return False, f"нет ответа за {wait}с"


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception as e:  # noqa: BLE001
        verdict(True, f"не разобрал вход: {e}")

    cmd = (payload.get("sources") or {}).get("command", "")
    if not cmd.strip():
        verdict(False, "не команда")

    what = classify(cmd)
    if not what:
        verdict(False, "не разрушительная операция")

    cfg = read_config()
    token = cfg.get("DBHUB_APPROVAL_BOT_TOKEN", "")
    chat = cfg.get("DBHUB_APPROVAL_CHAT_ID", "")
    if not token or not chat:
        verdict(True, f"{what}: подтвердить некому — нет конфига {CONFIG}")

    try:
        wait = int(cfg.get("DBHUB_APPROVAL_TIMEOUT", "540"))
    except ValueError:
        wait = 540

    host = os.uname().nodename
    ok, reason = ask_telegram(token, chat, host, cmd, what, wait)
    if ok:
        try:
            with open(os.path.join(HOME, ".claude/destructive-approved.log"), "a") as f:
                f.write(f"{time.strftime('%F %T')}\t{host}\t{what}\t{cmd}\n")
        except OSError:
            pass
        verdict(False, f"{what}: {reason}")
    verdict(True, f"{what}: {reason}")


if __name__ == "__main__":
    main()
