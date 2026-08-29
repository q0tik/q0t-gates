#!/usr/bin/env python3
"""В воркспейсе есть репозиторий, которого нет в реестре.

Реестр ценен ровно тем, что полон: агент не станет искать репозиторий, о котором
не знает, — это и есть та самая несклеенная композиция фактов. Неполный реестр
молча возвращает проблему, ради которой заведён.

Срабатывает только когда в сессии реально работали с этим репозиторием: напоминать
про все незаполненные строки на каждом Stop — это шум, который научатся игнорировать.
"""
import json
import os
import re
import sys

WORKSPACE = os.path.expanduser("~/Developer/QB")
REGISTRY = os.path.join(WORKSPACE, ".claude/registry.md")
SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def repos() -> set[str]:
    out = set()
    if not os.path.isdir(WORKSPACE):
        return out
    for lvl1 in sorted(os.listdir(WORKSPACE)):
        p1 = os.path.join(WORKSPACE, lvl1)
        if not os.path.isdir(p1) or lvl1.startswith(".") or lvl1 in SKIP:
            continue
        if os.path.exists(os.path.join(p1, ".git")):
            out.add(lvl1)
            continue
        for lvl2 in sorted(os.listdir(p1)):
            if os.path.exists(os.path.join(p1, lvl2, ".git")):
                out.add(f"{lvl1}/{lvl2}")
    return out


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"violated": False, "reason": f"не разобрал вход: {e}"}))
        return

    try:
        reg = open(REGISTRY, encoding="utf-8", errors="replace").read()
    except OSError:
        print(json.dumps({"violated": False, "reason": "реестра нет — правило неприменимо"}))
        return

    listed = set(re.findall(r"^\|\s*`([^`]+)`", reg, re.M))
    missing = repos() - listed
    if not missing:
        print(json.dumps({"violated": False, "reason": "реестр полон"}))
        return

    # Только те, что реально трогали в сессии.
    transcript = payload.get("sources", {}).get("transcript", "")
    touched = sorted(r for r in missing if r in transcript)
    if not touched:
        print(json.dumps({"violated": False, "reason": f"вне реестра {len(missing)}, но в сессии их не трогали"}))
        return

    print(json.dumps({
        "violated": True,
        "reason": "нет в реестре: " + ", ".join(touched[:5]),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
