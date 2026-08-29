#!/usr/bin/env python3
"""Реестр сущностей — таблица связей, которая грузится в каждую сессию.

Зачем: модели плохо склеивают два разнесённых факта. «В QB нельзя X» + «репозиторий Y
относится к QB» по отдельности известны, а вместе не сходятся. Реестр убирает сам шаг
композиции: связь не выводится, а лежит готовой.

Поиск (vault, RAG) эту задачу не решает — он работает, когда знаешь, что искать, а здесь
вопрос не задан вовсе. Поэтому реестр маленький и грузится всегда, а не ищется.

Машинные колонки собирает скрипт, смысловые пишет человек — и они переживают перегенерацию:
реестр, который надо целиком поддерживать руками, устареет за месяц.

    python3 tools/registry.py <workspace> -o <registry.md>
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Смысловые колонки: скрипт их не выдумывает, только переносит из старой версии.
MANUAL_COLS = ["назначение / что ломает", "среда"]
AUTO_COLS = ["репозиторий", "стек", "деплой", "активность"]

STACK_MARKERS = [
    ("*.py", "python"), ("*.go", "go"), ("*.vue", "vue"),
    ("*.ts", "ts"), ("*.tsx", "ts"), ("*.js", "js"),
    ("*.gd", "gdscript"), ("*.sql", "sql"), ("*.java", "java"),
    ("*.rs", "rust"), ("*.tf", "terraform"),
]

SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor"}


def git(repo: Path, *args: str) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def stack_of(repo: Path) -> str:
    counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in __import__("os").walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP and not d.startswith(".")]
        for f in filenames:
            suf = Path(f).suffix
            for pat, lang in STACK_MARKERS:
                if suf == pat[1:]:
                    counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return "—"
    top = sorted(counts.items(), key=lambda x: -x[1])[:2]
    return "+".join(lang for lang, _ in top)


def deploy_of(repo: Path) -> str:
    marks = []
    if (repo / "Dockerfile").exists() or list(repo.glob("*/Dockerfile")):
        marks.append("docker")
    if (repo / ".gitlab-ci.yml").exists():
        marks.append("ci")
    if list(repo.glob("*.nomad")) or list(repo.glob("**/*.nomad.hcl"))[:1]:
        marks.append("nomad")
    if (repo / "pyproject.toml").exists() and re.search(
        r'^\s*\[project\]|^\s*\[tool\.poetry\]',
        (repo / "pyproject.toml").read_text(errors="replace"), re.M,
    ):
        # библиотека, если нет Dockerfile — публикуется, а не деплоится
        if "docker" not in marks:
            marks.append("пакет")
    return ",".join(marks) if marks else "—"


def activity_of(repo: Path) -> str:
    last = git(repo, "log", "-1", "--format=%cs")
    if not last:
        return "—"
    n = git(repo, "rev-list", "--count", "--since=6.months.ago", "HEAD")
    return f"{last} ({n} за 6мес)" if n and n != "0" else f"{last} (тихо)"


def find_repos(workspace: Path) -> list[Path]:
    """Репозитории лежат не только на верхнем уровне — часть вложена."""
    out = []
    for lvl1 in sorted(workspace.iterdir()):
        if not lvl1.is_dir() or lvl1.name.startswith(".") or lvl1.name in SKIP:
            continue
        if (lvl1 / ".git").exists():
            out.append(lvl1)
            continue
        for lvl2 in sorted(lvl1.iterdir()):
            if lvl2.is_dir() and (lvl2 / ".git").exists():
                out.append(lvl2)
    return out


def read_manual(path: Path) -> dict[str, dict[str, str]]:
    """Смысловые колонки из предыдущей версии — по имени репозитория."""
    if not path.exists():
        return {}
    kept: dict[str, dict[str, str]] = {}
    header: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not header:
            header = [c.lower() for c in cells]
            continue
        if all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        row = dict(zip(header, cells))
        name = row.get("репозиторий", "").strip("`")
        if name:
            kept[name] = {c: row.get(c, "") for c in MANUAL_COLS}
    return kept


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    out = Path(args.out).expanduser()
    manual = read_manual(out)

    rows = []
    for repo in find_repos(ws):
        name = str(repo.relative_to(ws))
        m = manual.get(name, {})
        rows.append({
            "репозиторий": f"`{name}`",
            "стек": stack_of(repo),
            "деплой": deploy_of(repo),
            "активность": activity_of(repo),
            "назначение / что ломает": m.get("назначение / что ломает", "**?**"),
            "среда": m.get("среда", "**?**"),
        })

    cols = ["репозиторий", "назначение / что ломает", "среда", "стек", "деплой", "активность"]
    # Без выравнивания: таблица грузится в КАЖДУЮ сессию, и padding — это
    # мегабайты пробелов за год. Markdown отрендерит и так.

    lines = [
        "<!-- СГЕНЕРИРОВАНО tools/registry.py — машинные колонки перезаписываются.",
        "     Колонки «назначение / что ломает» и «среда» пишутся руками и сохраняются",
        "     при перегенерации. `**?**` = не заполнено, заполни при следующем касании. -->",
        "",
        f"# Реестр репозиториев {ws.name}",
        "",
        "Связь «репозиторий → чей он и что ломает» лежит здесь готовой, чтобы её не надо",
        "было выводить. Обновить: `python3 ~/Developer/q0t-gates/tools/registry.py "
        f"{ws} -o {out}`",
        "",
        "| " + " | ".join(cols) + " |",
        "|" + "|".join("---" for _ in cols) + "|",
    ]
    for r in sorted(rows, key=lambda x: x["репозиторий"]):
        lines.append("| " + " | ".join(r[c] for c in cols) + " |")

    unfilled = sum(1 for r in rows if "**?**" in (r["назначение / что ломает"] + r["среда"]))
    lines += ["", f"Всего репозиториев: {len(rows)}. Без описания: {unfilled}."]

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n")
    print(f"{out}: {len(rows)} репозиториев, без описания {unfilled}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
