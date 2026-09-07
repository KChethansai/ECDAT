"""Deterministic dead-code detection. Certainty is earned, never assumed.

DEAD_CODE only when: symbol unreferenced anywhere AND module has no dynamic
markers AND symbol is not public/entry (dunder, __all__, main guard, test,
exported). Everything else uncertain is POTENTIAL_DEAD_CODE with LOW/MEDIUM.
"""

from __future__ import annotations

import ast
import re

from .models import CodeFinding
from .scope import read_text, redact
from .symbols import ModuleInfo, cross_references

ENTRY_NAMES = {"main", "__main__", "setup", "teardown", "run", "execute", "cli", "app"}
TEST_MARKERS = ("test_", "_test", "tests", "conftest", "assert")


def _is_test_file(rel: str) -> bool:
    lowered = rel.lower()
    return any(marker in lowered for marker in TEST_MARKERS)


def _is_public(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") or not name.startswith("_")


def _unused_imports(mod: ModuleInfo, tree: ast.AST | None) -> list[CodeFinding]:
    if mod.language != "python" or tree is None:
        return []
    # Import bindings are alias nodes, not Name nodes: zero Name occurrences
    # means the import is genuinely unreferenced in this module.
    findings = []
    counts: dict[str, int] = {}
    dunder_all: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            # Import bindings are alias nodes, not Name nodes, so every Name
            # occurrence is a genuine use; zero means unused.
            counts[node.id] = counts.get(node.id, 0) + 1
        elif (isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)):
            for child in ast.walk(node.value):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    dunder_all.add(child.value.split(".")[0])
    for local, info in sorted(mod.imports.items()):
        if info["source"] == "__future__":
            continue  # compiler directive, never "unused"
        if counts.get(local, 0) == 0 and local not in dunder_all:
            findings.append(CodeFinding(
                analyzer="dead_code", category="DEAD_CODE", file_path=mod.rel,
                line=info["lineno"], symbol=local,
                title=f"Unused import `{local}`",
                description=(f"`{local}` is imported from `{info['source']}` but never "
                             f"referenced in this module."),
                evidence=redact(f"import of {local} from {info['source']}"),
                confidence="HIGH", verdict="DEAD_CODE", impact="LOW", effort="SMALL",
                risk="LOW",
                rationale="Import binding has zero Name occurrences in the module.",
                verification="Remove the import and run the project's test suite / type check.",
                deterministic=True))
    return findings


def _unreachable(mod: ModuleInfo, tree: ast.AST | None) -> list[CodeFinding]:
    if mod.language != "python" or tree is None:
        return []
    findings: list[CodeFinding] = []

    def check_block(stmts: list[ast.stmt]) -> None:
        terminated = False
        for stmt in stmts:
            if terminated and not isinstance(stmt, ast.Expr):
                findings.append(CodeFinding(
                    analyzer="dead_code", category="DEAD_CODE", file_path=mod.rel,
                    line=stmt.lineno, symbol="",
                    title=f"Unreachable statement (line {stmt.lineno})",
                    description="Statement follows return/raise/break/continue in the same block.",
                    evidence=redact(ast.dump(stmt)[:160]),
                    confidence="HIGH", verdict="DEAD_CODE", impact="LOW", effort="SMALL",
                    risk="LOW",
                    rationale="Control flow cannot reach past a terminating statement.",
                    verification="Remove the statement; tests must still pass.",
                    deterministic=True))
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.For, ast.While, ast.If, ast.With, ast.Try)):
                for field in ("body", "orelse", "finalbody"):
                    body = getattr(node, field, None)
                    if isinstance(body, list) and body:
                        check_block(body)

    check_block(tree.body)
    # de-duplicate by line (nested walk can revisit)
    seen, unique = set(), []
    for finding in findings:
        if finding.line not in seen:
            seen.add(finding.line)
            unique.append(finding)
    return unique


def _unused_variables(mod: ModuleInfo, tree: ast.AST | None) -> list[CodeFinding]:
    if mod.language != "python" or tree is None:
        return []
    findings: list[CodeFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        loaded: set[str] = set()
        stored: dict[str, int] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                loaded.add(child.id)
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                stored.setdefault(child.id, child.lineno)
            elif isinstance(child, ast.arg) and child.arg not in ("self", "cls", "_"):
                stored.setdefault(child.arg, child.lineno if hasattr(child, "lineno") else node.lineno)
        params = {a.arg for a in node.args.args + node.args.kwonlyargs}
        for name, lineno in sorted(stored.items()):
            if name.startswith("_") or name in loaded or name in params and name in ("self", "cls"):
                continue
            if name in params:
                continue  # unused args are API surface; handled as POTENTIAL below
            findings.append(CodeFinding(
                analyzer="dead_code", category="DEAD_CODE", file_path=mod.rel,
                line=lineno, symbol=name,
                title=f"Unused local variable `{name}` in `{node.name}`",
                description=f"`{name}` is assigned but never read inside `{node.name}`.",
                evidence=redact(f"{name} assigned in {node.name}, never loaded"),
                confidence="MEDIUM", verdict="POTENTIAL_DEAD_CODE", impact="LOW",
                effort="SMALL", risk="LOW",
                rationale="No Load of this name in the function scope (closures may still capture).",
                verification="Remove the assignment; tests must still pass.",
                deterministic=True))
    return findings


def analyze(modules: dict[str, ModuleInfo],
              trees: dict[str, ast.AST | None] | None = None) -> list[CodeFinding]:
    from .symbols import parse_tree

    refs = cross_references(modules)
    findings: list[CodeFinding] = []
    for rel, mod in sorted(modules.items()):
        tree = trees.get(rel) if trees is not None else parse_tree(mod)
        findings.extend(_unused_imports(mod, tree))
        findings.extend(_unreachable(mod, tree))
        findings.extend(_unused_variables(mod, tree))
        test_file = _is_test_file(rel)
        for name, info in sorted(mod.defs.items()):
            if mod.language == "javascript":
                continue  # JS handled below at reduced confidence
            if name in ENTRY_NAMES or (_is_public(name) and mod.dynamic):
                continue
            # Def names are not Name nodes; referenced = loaded in its module or others.
            other_refs = {r for r in refs.get(name, set()) if r != rel}
            same_mod_ref = name in mod.names_used
            if other_refs or same_mod_ref:
                continue
            if (test_file or info["decorated"] or _is_public(name) or mod.dynamic
                    or (mod.has_main_guard and name == "main")):
                findings.append(CodeFinding(
                    analyzer="dead_code", category="DEAD_CODE", file_path=rel,
                    line=info["lineno"], symbol=name,
                    title=f"Potentially unused {info['kind']} `{name}`",
                    description=(f"`{name}` has no static references. It may be a public API, "
                                 f"framework hook, or dynamically loaded symbol."),
                    evidence=redact(f"{info['kind']} {name} defined at line {info['lineno']}, no references"),
                    confidence="LOW", verdict="POTENTIAL_DEAD_CODE", impact="LOW",
                    effort="SMALL", risk="MEDIUM",
                    rationale="No static reference found, but public/dynamic context forbids certainty.",
                    verification="Confirm no dynamic/config/test reference, then remove and run tests.",
                    deterministic=True))
            else:
                findings.append(CodeFinding(
                    analyzer="dead_code", category="DEAD_CODE", file_path=rel,
                    line=info["lineno"], symbol=name,
                    title=f"Unused {info['kind']} `{name}`",
                    description=(f"`{name}` is defined but never referenced in the analyzed scope."),
                    evidence=redact(f"{info['kind']} {name} defined at line {info['lineno']}, no references"),
                    confidence="MEDIUM", verdict="POTENTIAL_DEAD_CODE", impact="LOW",
                    effort="SMALL", risk="MEDIUM",
                    rationale="No static reference in module or cross-module graph.",
                    verification="Confirm no dynamic reference, then remove and run tests.",
                    deterministic=True))
        if mod.language == "javascript":
            text = read_text(mod.path) or ""
            for name, info in sorted(mod.defs.items()):
                if info["exported"] or len(name) < 3:
                    continue
                uses = len(re.findall(rf"\b{re.escape(name)}\b", text))
                if uses <= 1 and name not in refs:
                    findings.append(CodeFinding(
                        analyzer="dead_code", category="DEAD_CODE", file_path=rel,
                        line=info["lineno"], symbol=name,
                        title=f"Potentially unused symbol `{name}`",
                        description=(f"`{name}` appears once (its definition) in heuristic JS analysis."),
                        evidence=redact(f"symbol {name} defined at line {info['lineno']}"),
                        confidence="LOW", verdict="POTENTIAL_DEAD_CODE", impact="LOW",
                        effort="SMALL", risk="MEDIUM",
                        rationale="JS analysis is textual; bundlers/frameworks may reference dynamically.",
                        verification="Confirm with bundler/IDE analysis, then remove and run tests.",
                        deterministic=False))
    return findings
