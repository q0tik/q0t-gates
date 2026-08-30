#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["tree-sitter", "tree-sitter-language-pack"]
# ///
"""Карта модулей репозитория — вход архитектурного ревьюера.

Единого способа разобрать все стеки нет, поэтому карта собирается тремя
независимыми слоями, различающимися надёжностью:

    слой 0  язык-агностичный: дерево, манифесты зависимостей, co-change из git
    слой 1  tree-sitter: символы верхнего уровня и импорты (~40 языков)
    слой 2  фреймворк-специфичный: эндпоинты (OpenAPI, иначе адаптер)

Отказ верхнего слоя не отменяет нижние. Главное правило вывода: **пропуск
данных не должен выглядеть как отсутствие сущности** — несработавший слой
пишет об этом прямо, иначе ревьюер выдаст «у сервиса нет API» на сервисе с
двадцатью ручками.

Запуск:
    uv run tools/modmap.py <path> [--changed a.py,b.py] [--commits N]

Без uv тоже работает: слой 1 помечается недоступным, остальное собирается.
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    from tree_sitter_language_pack import get_parser

    TREE_SITTER = True
except Exception:  # noqa: BLE001 — слой опционален по замыслу
    TREE_SITTER = False

TEST_DIRS = {"tests", "test", "spec", "__tests__", "testdata", "e2e"}
TEST_FILE_RE = re.compile(r"(^test_|_test\.|\.test\.|\.spec\.|conftest\.py$)")

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "env",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "vendor", ".idea", ".vscode", "htmlcov", ".next", "target",
}

LANG_BY_EXT = {
    ".py": "python", ".go": "go", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".vue": "vue", ".rb": "ruby",
    ".rs": "rust", ".java": "java", ".kt": "kotlin", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cs": "csharp",
    ".gd": "gdscript", ".sh": "bash", ".sql": "sql",
}

# Узлы верхнего уровня, которые считаем публичным интерфейсом модуля.
SYMBOL_NODES = {
    "python": {"function_definition": "def", "class_definition": "class"},
    "go": {"function_declaration": "func", "method_declaration": "method",
           "type_declaration": "type"},
    "javascript": {"function_declaration": "function", "class_declaration": "class"},
    "typescript": {"function_declaration": "function", "class_declaration": "class",
                   "interface_declaration": "interface", "type_alias_declaration": "type"},
    "ruby": {"method": "def", "class": "class", "module": "module"},
    "rust": {"function_item": "fn", "struct_item": "struct", "trait_item": "trait"},
    "java": {"class_declaration": "class", "interface_declaration": "interface"},
}

IMPORT_NODES = {
    "python": {"import_statement", "import_from_statement"},
    "go": {"import_declaration"},
    "javascript": {"import_statement"},
    "typescript": {"import_statement"},
    "rust": {"use_declaration"},
    "java": {"import_declaration"},
}

MANIFESTS = [
    "requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
    "go.mod", "package.json", "pom.xml", "build.gradle", "Cargo.toml",
    "Gemfile", "composer.json",
]


# ───────────────────────────── слой 0 ─────────────────────────────

def walk_files(root: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        if TEST_DIRS & set(Path(dirpath).parts):
            continue
        for f in filenames:
            if TEST_FILE_RE.search(f):
                continue
            p = Path(dirpath) / f
            if p.suffix in LANG_BY_EXT:
                out.append(p)
    return sorted(out)


def tree_summary(root: Path, files: list[Path]) -> str:
    """Дерево агрегируется по модулям: список из 383 файлов бесполезен агенту."""
    by_dir: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for f in files:
        rel = f.relative_to(root)
        mod = str(rel.parent) if str(rel.parent) != "." else "(корень)"
        by_dir[mod][LANG_BY_EXT[f.suffix]] += 1

    lines = []
    for mod in sorted(by_dir):
        langs = ", ".join(f"{n} {lang}" for lang, n in by_dir[mod].most_common())
        lines.append(f"  {mod:<45} {langs}")
    return "\n".join(lines) if lines else "  (файлов с кодом не найдено)"


def dependencies(root: Path) -> str:
    found = []
    for name in MANIFESTS:
        p = root / name
        if not p.exists():
            continue
        try:
            body = p.read_text(errors="replace")
        except OSError:
            continue
        found.append(f"  {name}:")
        for dep in parse_manifest(name, body)[:40]:
            found.append(f"    {dep}")
    return "\n".join(found) if found else "  (манифестов зависимостей не найдено)"


def parse_manifest(name: str, body: str) -> list[str]:
    if name == "requirements.txt":
        return [l.strip() for l in body.splitlines()
                if l.strip() and not l.strip().startswith("#")]
    if name == "go.mod":
        return re.findall(r"^\s+([\w./-]+)\s+v[\d.]", body, re.M)
    if name == "package.json":
        try:
            d = json.loads(body)
        except json.JSONDecodeError:
            return []
        return sorted({**d.get("dependencies", {}), **d.get("devDependencies", {})})
    if name == "pyproject.toml":
        # Только секции зависимостей: наивный разбор всего файла затягивает
        # ignore-коды ruff и прочие настройки инструментов.
        deps: list[str] = []
        for block in re.findall(r"^dependencies\s*=\s*\[(.*?)\]", body, re.M | re.S):
            deps += re.findall(r'"([A-Za-z0-9_.\[\]-]+)', block)
        poetry = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?=^\[|\Z)", body, re.M | re.S)
        if poetry:
            deps += re.findall(r"^([A-Za-z0-9_.-]+)\s*=", poetry.group(1), re.M)
        return sorted(set(deps))
    if name == "Cargo.toml":
        return re.findall(r"^([\w-]+)\s*=", body.split("[dependencies]")[-1], re.M)
    return []


def co_change(root: Path, commits: int) -> str:
    """Связность по истории: какие файлы меняются вместе.

    Работает на любом стеке, потому что читает историю, а не синтаксис. Для
    вопроса «выросла ли связность» это часто прямее графа импортов: импорт
    бывает формальным, а совместное изменение — факт.
    """
    try:
        out = subprocess.run(
            ["git", "log", f"-{commits}", "--format=@%H", "--name-only"],
            cwd=root, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "  (git недоступен)"
    if out.returncode != 0:
        return "  (не git-репозиторий — связность по истории недоступна)"

    pairs: collections.Counter = collections.Counter()
    current: list[str] = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("@"):
            files = sorted({
                f for f in current
                if Path(f).suffix in LANG_BY_EXT
                and not TEST_FILE_RE.search(Path(f).name)
                and not (TEST_DIRS & set(Path(f).parts))
            })
            # Мега-коммиты (рефакторинг всего репозитория) связывают всё со всем
            # и забивают сигнал — пропускаем.
            if 2 <= len(files) <= 15:
                pairs.update(itertools.combinations(files, 2))
            current = []
        elif line:
            current.append(line)

    top = [(p, n) for p, n in pairs.most_common(15) if n >= 3]
    if not top:
        return f"  (за последние {commits} коммитов устойчивых пар не видно)"
    return "\n".join(f"  {n:2}×  {a}  ↔  {b}" for (a, b), n in top)


def package_name(root: Path) -> str:
    """Имя пакета — по нему ищутся потребители."""
    py = root / "pyproject.toml"
    if py.exists():
        m = re.search(r'^name\s*=\s*"([^"]+)"', py.read_text(errors="replace"), re.M)
        if m:
            return m.group(1)
    gomod = root / "go.mod"
    if gomod.exists():
        m = re.search(r"^module\s+(\S+)", gomod.read_text(errors="replace"), re.M)
        if m:
            return m.group(1)
    pkg = root / "package.json"
    if pkg.exists():
        try:
            return json.loads(pkg.read_text()).get("name", "")
        except json.JSONDecodeError:
            pass
    return ""


def consumers(root: Path) -> str:
    """Кто снаружи зависит от этого репозитория и на какой версии.

    Карта одного репозитория структурно недостаточна для библиотеки: раздел
    «Импорты между модулями» показывает только внутрипакетные рёбра, а самое
    дорогое у библиотеки — внешние потребители и разъехавшиеся пины. Этот
    раздел добавлен после первого же боевого ревью, где ревьюер сам сообщил,
    что находки пришлось добывать грепом по соседним репозиториям.
    """
    name = package_name(root)
    if not name:
        return "  (имя пакета не определено — потребителей не искали)"

    workspace = root.parent
    variants = {name, name.replace("-", "_"), name.replace("_", "-")}
    rows: list[str] = []

    # Репозитории лежат не только соседями: в QB часть сервисов вложена
    # (janus_old/janus_transfers_eda). Ищем на два уровня вглубь.
    candidates: list[Path] = []
    for lvl1 in sorted(workspace.iterdir()):
        if not lvl1.is_dir() or lvl1.name in SKIP_DIRS:
            continue
        candidates.append(lvl1)
        if not (lvl1 / ".git").exists():
            candidates.extend(d for d in sorted(lvl1.iterdir()) if d.is_dir())

    for sibling in candidates:
        if sibling == root or not (sibling / ".git").exists():
            continue
        for manifest in ("pyproject.toml", "requirements.txt", "go.mod", "package.json"):
            mf = sibling / manifest
            if not mf.exists():
                continue
            try:
                body = mf.read_text(errors="replace")
            except OSError:
                continue
            for v in variants:
                for line in body.splitlines():
                    if v in line and not line.strip().startswith("#"):
                        label = str(sibling.relative_to(workspace))
                        rows.append(f"  {label:<38} {manifest:<16} {line.strip()[:90]}")
                        break

    if not rows:
        return (f"  (пакет `{name}`: потребителей среди соседних репозиториев не найдено —\n"
                f"   искали только в {workspace}, монорепо и внешние потребители сюда не попадают)")
    uniq = sorted(set(rows))
    return (f"  пакет `{name}`, потребители в {workspace.name}/:\n" + "\n".join(uniq)
            + "\n  ⚠ разные версии в пинах = потребители на разных линиях библиотеки")


# ───────────────────────────── слой 1 ─────────────────────────────

def symbols_and_imports(root: Path, files: list[Path], changed: set[str]):
    """Символы верхнего уровня и импорты через tree-sitter.

    Для изменённых файлов печатаются сами символы; для остальных — только
    счётчик по модулю: карта должна помещаться в контекст, а список всех
    символов сервиса на 383 файла в него не помещается.
    """
    if not TREE_SITTER:
        return (
            "  (не извлечены: tree-sitter недоступен — запусти через `uv run tools/modmap.py`.\n"
            "   НЕ считать, что символов нет)",
            "  (не извлечены: tree-sitter недоступен)",
        )

    detailed: list[str] = []
    per_module: collections.Counter = collections.Counter()
    edges: collections.Counter = collections.Counter()
    parsers: dict[str, object] = {}

    for f in files:
        lang = LANG_BY_EXT[f.suffix]
        if lang not in SYMBOL_NODES and lang not in IMPORT_NODES:
            continue
        if lang not in parsers:
            try:
                parsers[lang] = get_parser(lang)
            except Exception:  # noqa: BLE001 — грамматики может не быть
                parsers[lang] = None
        parser = parsers[lang]
        if parser is None:
            continue

        try:
            src = f.read_bytes()
        except OSError:
            continue
        try:
            tree = parser.parse(src)
        except Exception:  # noqa: BLE001
            continue

        rel = str(f.relative_to(root))
        kinds = SYMBOL_NODES.get(lang, {})
        imports = IMPORT_NODES.get(lang, set())
        is_changed = rel in changed

        for node in tree.root_node.children:
            # Декорированные определения tree-sitter оборачивает в
            # decorated_definition: без разворачивания все @dataclass-классы и
            # @app.get-функции просто не видны в карте.
            if node.type in ("decorated_definition", "export_statement"):
                inner = [c for c in node.children if c.type in kinds]
                node = inner[0] if inner else node
            if node.type in kinds:
                per_module[str(Path(rel).parent)] += 1
                if is_changed:
                    name = node_name(node, src)
                    if name:
                        detailed.append(f"  {kinds[node.type]:<9} {name:<38} {rel}:{node.start_point[0] + 1}")
            elif node.type in imports:
                target = local_import(src[node.start_byte:node.end_byte].decode("utf8", "replace"), root)
                if target:
                    edges[(str(Path(rel).parent), target)] += 1

    sym_txt = "\n".join(detailed) if detailed else "  (в изменённых файлах символов верхнего уровня нет)"
    if per_module:
        sym_txt += "\n\n  символов по модулям (весь репозиторий):\n"
        sym_txt += "\n".join(f"    {m:<45} {n}" for m, n in sorted(per_module.items()))

    if edges:
        imp_txt = "\n".join(f"  {n:2}×  {a}  →  {b}" for (a, b), n in edges.most_common(20))
        imp_txt += "\n" + structure_signals(edges)
    else:
        imp_txt = "  (внутренних импортов между модулями не обнаружено)"
    return sym_txt, imp_txt


def structure_signals(edges: collections.Counter) -> str:
    """Циклы и перекос связности — то, ради чего граф вообще нужен.

    Сам по себе список рёбер архитектору мало что говорит: он его не удержит и
    выводов из него не сделает. Выводы делают две вещи — цикл (модули нельзя
    менять и тестировать по отдельности) и перекос fan-in/fan-out (модуль, от
    которого зависит всё, дорожает при каждой правке).
    """
    # Рёбра между директориями: logic.models.stevia → logic/models
    graph: dict[str, set[str]] = collections.defaultdict(set)
    for (src, dotted), _ in edges.items():
        dst = str(Path(dotted.replace(".", "/")).parent)
        if dst in (".", "") or dst == src:
            continue
        graph[src].add(dst)

    out = []

    if cycles := find_cycles(graph):
        out.append("\n  ⚠ ЦИКЛЫ (модули нельзя изменить и протестировать по отдельности):")
        for c in cycles[:5]:
            out.append("      " + " → ".join(c + [c[0]]))

    fan_in: collections.Counter = collections.Counter()
    for src, dsts in graph.items():
        for d in dsts:
            fan_in[d] += 1
    if fan_in:
        top = fan_in.most_common(3)
        if top[0][1] >= 2:
            out.append("\n  Кто держит систему (fan-in — сколько модулей зависит):")
            for mod, n in top:
                out.append(f"      {mod:<38} ← {n}")
            out.append("      правка модуля с высоким fan-in задевает всех, кто на него смотрит")
    return "\n".join(out)


def find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Обычный обход в глубину со стеком: графы модулей маленькие."""
    found: list[list[str]] = []
    state: dict[str, int] = {}  # 0 — не был, 1 — в стеке, 2 — закрыт

    def walk(node: str, stack: list[str]) -> None:
        state[node] = 1
        stack.append(node)
        for nxt in sorted(graph.get(node, ())):
            if state.get(nxt, 0) == 1:
                found.append(stack[stack.index(nxt):])
            elif state.get(nxt, 0) == 0:
                walk(nxt, stack)
        stack.pop()
        state[node] = 2

    for n in sorted(graph):
        if state.get(n, 0) == 0:
            walk(n, [])
    return found


def node_name(node, src: bytes) -> str:
    for child in node.children:
        if child.type in ("identifier", "type_identifier", "dotted_name", "field_identifier"):
            return src[child.start_byte:child.end_byte].decode("utf8", "replace")
    return ""


def local_import(text: str, root: Path) -> str:
    """Оставляем только импорты внутри репозитория — внешние уже в зависимостях."""
    m = re.search(r"from\s+([\w.]+)\s+import|import\s+\"?([\w./-]+)", text)
    if not m:
        return ""
    mod = (m.group(1) or m.group(2) or "").strip('"')
    head = mod.replace(".", "/").split("/")[0]
    if not head:
        return ""
    return mod if (root / head).exists() else ""


# ───────────────────────────── слой 2 ─────────────────────────────

ENDPOINT_RE = re.compile(
    r"@(?:\w+)\.(get|post|put|patch|delete|head|options)\s*\(\s*[\"']([^\"']+)",
    re.I,
)
# Без требования пути со слэша сюда попадает любой вызов .Get(…)/.Delete(…) —
# на реальном репозитории это дало «DELETE base» из методов работы с хранилищем.
GO_ROUTE_RE = re.compile(
    r"\.(Get|Post|Put|Patch|Delete|Head|Options|HandleFunc)\s*\(\s*\"(/[^\"]*)\"",
)


def endpoints(root: Path, files: list[Path]) -> tuple[str, str]:
    """Эндпоинты — единственное место, где фреймворк реально важен."""
    for name in ("openapi.json", "swagger.json", "docs/openapi.json"):
        p = root / name
        if p.exists():
            try:
                spec = json.loads(p.read_text())
                rows = [f"  {m.upper():<7} {path}"
                        for path, ops in spec.get("paths", {}).items()
                        for m in ops]
                if rows:
                    return "\n".join(sorted(rows)), f"слой 2: OpenAPI ({name})"
            except (OSError, json.JSONDecodeError):
                pass

    langs = {LANG_BY_EXT[f.suffix] for f in files}
    rows, adapters = [], []

    if "python" in langs:
        adapters.append("FastAPI/Flask")
        for f in (x for x in files if x.suffix == ".py"):
            try:
                body = f.read_text(errors="replace")
            except OSError:
                continue
            for method, path in ENDPOINT_RE.findall(body):
                rows.append(f"  {method.upper():<7} {path:<40} {f.relative_to(root)}")

    if "go" in langs:
        adapters.append("net/http, chi, gin")
        for f in (x for x in files if x.suffix == ".go"):
            try:
                body = f.read_text(errors="replace")
            except OSError:
                continue
            for method, path in GO_ROUTE_RE.findall(body):
                rows.append(f"  {method.upper():<7} {path:<40} {f.relative_to(root)}")

    unknown = langs - {"python", "go", "javascript", "typescript", "vue", "sql", "bash"}
    gap = ""
    if unknown:
        # Пропуск данных не должен выглядеть как отсутствие сущности: даже если
        # часть эндпоинтов извлечена, о непокрытых стеках надо сказать прямо.
        gap = (f"\n  ⚠ файлы на {', '.join(sorted(unknown))} НЕ разобраны — "
               f"адаптера нет. НЕ считать, что там эндпоинтов нет.")

    if rows:
        return "\n".join(sorted(set(rows))) + gap, "слой 2: " + ", ".join(adapters)
    if unknown:
        return (f"  (не извлечены: нет адаптера для {', '.join(sorted(unknown))} — "
                f"НЕ считать, что эндпоинтов нет)"), "слой 2: адаптера нет"
    if not adapters:
        return "  (нет применимых адаптеров для стеков этого репозитория)", "слой 2: адаптера нет"
    return "  (эндпоинтов не найдено — адаптер для этого стека есть, значит их правда нет)", \
        "слой 2: " + ", ".join(adapters)


# ───────────────────────────── сборка ─────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="Карта модулей для архитектурного ревью")
    ap.add_argument("path")
    ap.add_argument("--changed", default="", help="файлы из дифа через запятую — по ним печатаются символы")
    ap.add_argument("--commits", type=int, default=200, help="глубина истории для co-change")
    args = ap.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"не директория: {root}", file=sys.stderr)
        return 1

    changed = {c.strip() for c in args.changed.split(",") if c.strip()}
    files = walk_files(root)

    sym, imp = symbols_and_imports(root, files, changed)
    eps, ep_layer = endpoints(root, files)
    sym_layer = "слой 1: tree-sitter" if TREE_SITTER else "слой 1: НЕДОСТУПЕН"

    print(f"# Карта модулей: {root.name}")
    print(f"файлов с кодом: {len(files)}")
    if changed:
        print(f"изменено в этом ревью: {', '.join(sorted(changed))}")
    print()
    print(f"## Модули                       [слой 0]\n{tree_summary(root, files)}\n")
    print(f"## Эндпоинты                    [{ep_layer}]\n{eps}\n")
    print(f"## Публичные символы            [{sym_layer}]\n{sym}\n")
    print(f"## Импорты между модулями       [{sym_layer}]\n{imp}\n")
    print(f"## Потребители пакета         [слой 0]\n{consumers(root)}\n")
    print(f"## Связность по истории         [слой 0, {args.commits} коммитов]\n{co_change(root, args.commits)}\n")
    print(f"## Зависимости                  [слой 0]\n{dependencies(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
