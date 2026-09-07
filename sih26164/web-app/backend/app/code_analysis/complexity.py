"""Complexity observations (never "bad code" verdicts): cyclomatic, nesting, size."""

from __future__ import annotations

import ast

from .models import CodeFinding
from .scope import redact
from .symbols import ModuleInfo

CYCLOMATIC_THRESHOLD = 10
NESTING_THRESHOLD = 4
LENGTH_THRESHOLD = 80
PARAMS_THRESHOLD = 6

BRANCH_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                ast.With, ast.AsyncWith, ast.BoolOp, ast.IfExp, ast.comprehension,
                ast.Assert, ast.Match)


def _complexity(node: ast.AST) -> tuple[int, int]:
    score, depth, deepest = 1, 0, 0
    stack = [(node, 0)]
    while stack:
        current, level = stack.pop()
        if isinstance(current, BRANCH_NODES):
            score += 1
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            level = 0
        elif isinstance(current, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
                                  ast.AsyncWith, ast.Try, ast.Match)):
            level += 1
            deepest = max(deepest, level)
        for child in ast.iter_child_nodes(current):
            stack.append((child, level))
    return score, deepest


def analyze(modules: dict[str, ModuleInfo],
              trees: dict[str, ast.AST | None] | None = None) -> list[CodeFinding]:
    from .symbols import parse_tree

    findings: list[CodeFinding] = []
    for rel, mod in sorted(modules.items()):
        if mod.language != "python":
            continue
        tree = trees.get(rel) if trees is not None else parse_tree(mod)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            score, depth = _complexity(node)
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            length = end - node.lineno + 1
            params = len(node.args.args) + len(node.args.kwonlyargs)
            flags = []
            if score >= CYCLOMATIC_THRESHOLD:
                flags.append(f"cyclomatic {score} (≥{CYCLOMATIC_THRESHOLD})")
            if depth >= NESTING_THRESHOLD:
                flags.append(f"nesting {depth} (≥{NESTING_THRESHOLD})")
            if length >= LENGTH_THRESHOLD:
                flags.append(f"{length} lines (≥{LENGTH_THRESHOLD})")
            if params >= PARAMS_THRESHOLD:
                flags.append(f"{params} params (≥{PARAMS_THRESHOLD})")
            if len(flags) < 2 and score < CYCLOMATIC_THRESHOLD:
                continue  # single mild flag below threshold is noise, not a finding
            findings.append(CodeFinding(
                analyzer="complexity", category="COMPLEXITY", file_path=rel,
                line=node.lineno, end_line=end, symbol=node.name,
                title=f"Complex function `{node.name}` ({', '.join(flags)})",
                description=(f"`{node.name}` exceeds complexity thresholds: {', '.join(flags)}. "
                             f"Framed as observation — complexity is sometimes inherent."),
                evidence=redact(f"def {node.name} with {', '.join(flags)}"),
                confidence="HIGH", verdict="COMPLEXITY_OBSERVATION",
                impact="MEDIUM" if score >= CYCLOMATIC_THRESHOLD * 2 else "LOW",
                effort="MEDIUM", risk="MEDIUM",
                rationale="High branching/nesting raises defect and review cost.",
                verification="Split or simplify; tests must still pass with identical behavior.",
                deterministic=True))
    return findings
