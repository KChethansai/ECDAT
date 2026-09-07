"""Lightweight symbol/reference graph: FILE -> SYMBOL -> REFERENCE.

Python: real AST (HIGH determinism). JS/TS: import/export + textual symbol
references (heuristic — findings built on it stay MEDIUM/LOW confidence).
Dynamic/framework hooks (decorators, __all__, route tables, string names)
downgrade certainty instead of being ignored.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .scope import language_of, read_text

JS_IMPORT_RE = re.compile(r"""import\s+(?:[^'"]*?from\s+)?['"]([^'"]+)['"]|"""
                          r"""require\(\s*['"]([^'"]+)['"]\s*\)|"""
                          r"""import\(\s*['"]([^'"]+)['"]\s*\)""")
JS_EXPORT_RE = re.compile(r"export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)|"
                          r"export\s*\{\s*([^}]*)\}")
JS_DEF_RE = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=|"
                       r"class\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{)")
JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "import",
               "export", "from", "class", "extends", "new", "typeof", "with", "do", "else"}
DYNAMIC_MARKERS = ("getattr", "globals(", "locals(", "eval(", "exec(", "__import__",
                   "importlib", "getattr(", "registry", "register", "route(", "add_route",
                   "urlpatterns", "router", "plugin", "entry_points", "setup(", "app.route")


class ModuleInfo:
    def __init__(self, path: Path, rel: str, language: str) -> None:
        self.path = path
        self.rel = rel
        self.language = language
        self.defs: dict[str, dict] = {}      # name -> {kind, lineno, end, exported, decorated}
        self.imports: dict[str, dict] = {}   # local name -> {source, lineno}
        self.names_used: set[str] = set()    # every loaded/stored name in the module
        self.strings: list[str] = []         # string literals (dynamic-ref hints)
        self.dynamic: bool = False           # dynamic loading markers seen
        self.has_main_guard: bool = False
        self.parse_ok: bool = True


def parse_python(path: Path, rel: str, text: str) -> ModuleInfo:
    mod = ModuleInfo(path, rel, "python")
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        mod.parse_ok = False
        return mod
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                mod.imports[local] = {"source": alias.name, "lineno": node.lineno}
                mod.names_used.add(local)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    mod.dynamic = True
                    continue
                local = alias.asname or alias.name
                mod.imports[local] = {"source": "." * node.level + (node.module or ""),
                                      "lineno": node.lineno}
                mod.names_used.add(local)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            mod.defs[node.name] = {"kind": kind, "lineno": node.lineno,
                                   "end": getattr(node, "end_lineno", node.lineno) or node.lineno,
                                   "exported": False,
                                   "decorated": bool(node.decorator_list)}
        elif isinstance(node, ast.Name):
            mod.names_used.add(node.id)
        elif isinstance(node, ast.Attribute):
            pass  # attribute roots surface as Name nodes already
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(mod.strings) < 200:
                mod.strings.append(node.value)
        elif isinstance(node, ast.Call):
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else "")
            if name in ("getattr", "eval", "exec", "__import__"):
                mod.dynamic = True
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            left = node.test.left
            if (isinstance(left, ast.Name) and left.id == "__name__"
                    and any(isinstance(c, ast.Constant) and c.value == "__main__"
                            for c in ast.walk(node.test))):
                mod.has_main_guard = True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    mod.dynamic = True  # public-API surface declared dynamically
    lowered = text.lower()
    if any(marker in lowered for marker in DYNAMIC_MARKERS):
        mod.dynamic = True
    return mod


def parse_javascript(path: Path, rel: str, text: str) -> ModuleInfo:
    mod = ModuleInfo(path, rel, "javascript")
    mod.parse_ok = True  # heuristic parse; confidence handled by analyzers
    for match in JS_IMPORT_RE.finditer(text):
        source = next(g for g in match.groups() if g)
        mod.imports[f"__import:{source}:{match.start()}"] = {"source": source,
                                                             "lineno": text.count("\n", 0, match.start()) + 1}
    for match in JS_EXPORT_RE.finditer(text):
        name = match.group(1)
        if name:
            mod.defs[name] = {"kind": "export", "lineno": text.count("\n", 0, match.start()) + 1,
                               "end": 0, "exported": True, "decorated": False}
        elif match.group(2):
            for part in match.group(2).split(","):
                name = part.strip().split(" as ")[-1].strip()
                if name:
                    mod.defs[name] = {"kind": "export", "lineno": text.count("\n", 0, match.start()) + 1,
                                       "end": 0, "exported": True, "decorated": False}
    for match in JS_DEF_RE.finditer(text):
        name = next((g for g in match.groups() if g), None)
        if name and name not in mod.defs and name not in JS_KEYWORDS:
            mod.defs[name] = {"kind": "function", "lineno": text.count("\n", 0, match.start()) + 1,
                               "end": 0, "exported": False, "decorated": False}
    mod.names_used = set(re.findall(r"[A-Za-z_$][\w$]*", text))
    lowered = text.lower()
    if any(marker in lowered for marker in DYNAMIC_MARKERS):
        mod.dynamic = True
    return mod


def parse_tree(mod: ModuleInfo) -> ast.AST | None:
    """Single shared Python parse per module; None when unavailable."""
    if mod.language != "python" or not mod.parse_ok:
        return None
    text = read_text(mod.path)
    if text is None:
        return None
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def build_graph(root: Path, files: list[Path]) -> dict[str, ModuleInfo]:
    """rel-path -> ModuleInfo. Pure static parse; never imports target code."""
    modules: dict[str, ModuleInfo] = {}
    for path in files:
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            continue
        lang = language_of(path)
        if lang not in ("python", "javascript"):
            continue
        text = read_text(path)
        if text is None:
            continue
        modules[rel] = (parse_python(path, rel, text) if lang == "python"
                        else parse_javascript(path, rel, text))
    return modules


def cross_references(modules: dict[str, ModuleInfo]) -> dict[str, set[str]]:
    """symbol name -> set of rel paths referencing it (excluding its own definition file)."""
    refs: dict[str, set[str]] = {}
    defined = {name for mod in modules.values() for name in mod.defs}
    for rel, mod in modules.items():
        for name in mod.names_used:
            if name in defined:
                refs.setdefault(name, set()).add(rel)
    return refs
