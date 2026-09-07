"""Statically inferable inefficiency patterns. Runtime claims need measurement.

Every finding here is POTENTIAL_PERFORMANCE_ISSUE (or OBSERVATION): static
analysis can show repeated work, never wall-clock cost.
"""

from __future__ import annotations

import ast
import re

from .models import CodeFinding
from .scope import read_text, redact
from .symbols import ModuleInfo

# Bare names that are expensive wherever called.
EXPENSIVE_BARE = {"open", "compile", "sleep", "connect"}
# Attribute calls expensive on typical I/O-ish receivers (matched by attr name;
# dict.get / list.sort style accessors are deliberately absent).
EXPENSIVE_ATTR = {"read", "readlines", "read_text", "loads", "load", "dumps", "dump",
                  "parse", "request", "fetch", "query", "execute"}
# get/post only count on network-ish receivers (requests.get, session.post, ...).
NETWORK_RECEIVERS = {"requests", "session", "http", "client", "api", "urllib",
                     "httpx", "aiohttp", "urlopen"}
LOOP_NODES = (ast.For, ast.AsyncFor, ast.While)
JS_LOOP_RE = re.compile(r"\b(for|while)\s*\(")


def _calls_in(node: ast.AST) -> list[tuple[str, int]]:
    out = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        lineno = getattr(child, "lineno", 0)
        if isinstance(func, ast.Name):
            if func.id in EXPENSIVE_BARE:
                out.append((func.id, lineno))
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            receiver = func.value.id if isinstance(func.value, ast.Name) else ""
            if receiver in ("ast", "asdict", "dataclasses"):
                continue  # in-memory model introspection, not I/O
            if attr in EXPENSIVE_ATTR:
                out.append((attr, lineno))
            elif attr in ("get", "post") and receiver in NETWORK_RECEIVERS:
                out.append((f"{receiver}.{attr}", lineno))
    return out


def _analyze_python(mod: ModuleInfo, tree: ast.AST) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    seen: set[tuple[str, int]] = set()  # nested loops revisit the same call sites
    for node in ast.walk(tree):
        if not isinstance(node, LOOP_NODES):
            continue
        lineno = getattr(node, "lineno", 0)
        for name, call_line in _calls_in(node):
            # Loop-invariance is undecidable cheaply — report POTENTIAL with hoisting option.
            if (name, call_line or lineno) in seen:
                continue
            seen.add((name, call_line or lineno))
            findings.append(CodeFinding(
                analyzer="efficiency", category="EFFICIENCY", file_path=mod.rel,
                line=call_line or lineno, symbol=name,
                title=f"Repeated `{name}` inside loop (line {call_line or lineno})",
                description=(f"`{name}` executes on every loop iteration. If its inputs do not "
                             f"change per iteration, hoisting it out removes repeated work."),
                evidence=redact(f"{name} called inside loop at line {call_line or lineno}"),
                confidence="MEDIUM", verdict="POTENTIAL_PERFORMANCE_ISSUE",
                impact="MEDIUM", effort="SMALL", risk="LOW",
                rationale="Repeated I/O/parse/compile in loops is a classic avoidable cost.",
                verification="Hoist and measure: profile before/after; tests must still pass.",
                deterministic=True))
        # Accumulation with += in a loop, excluding trivial numeric folding (s += i).
        for child in ast.walk(node):
            if (isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add)
                    and isinstance(child.target, ast.Name)
                    and not isinstance(child.value, (ast.Name, ast.Constant))):
                findings.append(CodeFinding(
                    analyzer="efficiency", category="EFFICIENCY", file_path=mod.rel,
                    line=child.lineno, symbol=child.target.id,
                    title=f"String/list accumulation with `+=` in loop (`{child.target.id}`)",
                    description=(f"`{child.target.id} += ...` inside a loop builds the result "
                                 f"incrementally; joining once is usually cheaper and clearer."),
                    evidence=redact(f"{child.target.id} += ... inside loop"),
                    confidence="LOW", verdict="POTENTIAL_PERFORMANCE_ISSUE",
                    impact="LOW", effort="SMALL", risk="LOW",
                    rationale="Quadratic copy behavior for long loops; harmless for short ones.",
                    verification="Rewrite with list+join; measure on realistic sizes.",
                    deterministic=True))
                break
        # Nested loops: O(n^2) shape worth a look, nothing more.
        nested = [c for c in ast.walk(node) if isinstance(c, LOOP_NODES) and c is not node]
        if nested:
            findings.append(CodeFinding(
                analyzer="efficiency", category="EFFICIENCY", file_path=mod.rel,
                line=lineno, symbol="",
                title=f"Nested loops (line {lineno}) — quadratic shape",
                description="A loop nested inside another loop; worth checking for set/dict "
                            "membership or early-exit alternatives.",
                evidence=redact(f"nested loop at line {lineno}"),
                confidence="LOW", verdict="POTENTIAL_PERFORMANCE_ISSUE",
                impact="MEDIUM", effort="MEDIUM", risk="LOW",
                rationale="Quadratic scaling only matters at size; many nested loops are fine.",
                verification="Profile with realistic input sizes before restructuring.",
                deterministic=True))
    return findings


def analyze(modules: dict[str, ModuleInfo],
              trees: dict[str, ast.AST | None] | None = None) -> list[CodeFinding]:
    from .symbols import parse_tree

    findings: list[CodeFinding] = []
    for rel, mod in sorted(modules.items()):
        if mod.language == "python":
            tree = trees.get(rel) if trees is not None else parse_tree(mod)
            if tree is not None:
                findings.extend(_analyze_python(mod, tree))
        elif mod.language == "javascript":
            text = read_text(mod.path)
            if text is None:
                continue
            for match in re.finditer(r"\b(JSON\.parse|JSON\.stringify|fetch|require)\s*\(", text):
                lineno = text.count("\n", 0, match.start()) + 1
                findings.append(CodeFinding(
                    analyzer="efficiency", category="EFFICIENCY", file_path=rel,
                    line=lineno, symbol=match.group(1),
                    title=f"Potentially repeated `{match.group(1)}` (line {lineno})",
                    description=(f"`{match.group(1)}` call site — check whether it sits in a "
                                 f"hot path or loop before acting."),
                    evidence=redact(f"{match.group(1)} at line {lineno}"),
                    confidence="LOW", verdict="POTENTIAL_PERFORMANCE_ISSUE",
                    impact="LOW", effort="SMALL", risk="LOW",
                    rationale="Heuristic JS scan; loop context not proven.",
                    verification="Inspect the call site; profile if it is in a loop.",
                    deterministic=False))
                if len([f for f in findings if f.file_path == rel]) > 10:
                    break
    return findings
