# System Architecture

```text
tools/ (reference only) ──╳──→ no imports into product code
obsidian-vault/ (Markdown) ←→ cli-agent MemoryProvider (sole reader/writer)
sih26164/cli-agent/ ──context──→ external coding agents (codex/claude/cursor-agent/agy)
sih26164/web-app/ ── FastAPI ↔ scanner pipeline ↔ CBOM ↔ Vite GUI
```

Boundaries: Vault=memory · git=history · (no app DB in MVP).
