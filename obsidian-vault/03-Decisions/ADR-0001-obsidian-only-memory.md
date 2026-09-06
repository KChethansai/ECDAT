# ADR-0001 — Obsidian Vault as the only AI/project memory

Date: 2026-09-06 · Status: accepted.

No Postgres/MySQL/SQLite/Mongo/Redis/vector DB for agent memory. Rationale: human-readable,
zero-dependency, versionable Markdown; matches ai-memory-vault conventions; keeps memory
auditable by judges. An app DB may appear later for runtime domain data only.
