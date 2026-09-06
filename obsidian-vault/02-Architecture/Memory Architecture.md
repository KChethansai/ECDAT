# Memory Architecture

```text
MemoryProvider (abstract: initialize/search/read/write/update/list/link)
└── ObsidianVaultProvider (Markdown files under OBSIDIAN_VAULT_PATH)
```

Retrieval per task: identify area → `search` vault (filename + content match) →
read top-N → compact context (capped chars) → send to agent.
Persistence after work: update the single owning note, link, don't duplicate.
The two-process demo proves fresh-process file reads (no cache, no DB, no hardcode).
