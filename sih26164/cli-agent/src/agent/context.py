"""Compact context builder: relevant context > maximum context."""

from __future__ import annotations

from .memory import ObsidianVaultProvider


def build_context(mem: ObsidianVaultProvider, task: str, max_chars: int = 4000,
                  top_n: int = 5) -> str:
    hits = mem.search(task, top_n=top_n)
    parts = [f"# Task\n{task}\n"]
    budget = max(0, max_chars - len(parts[0]))
    for rel, snippet in hits:
        try:
            body = mem.read(rel)[:1500]
        except OSError:
            continue
        chunk = f"\n## {rel}\n{body}\n"
        if len(chunk) > budget:
            chunk = chunk[:budget]
        parts.append(chunk)
        budget -= len(chunk)
        if budget <= 0:
            break
    parts.append(f"\n# Grounding ({len(hits)} vault notes consulted; snippets truncated)")
    return "".join(parts)
