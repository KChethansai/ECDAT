# VAULT-INDEX

Operating manual for this vault. Boot configs (CLI `config/`, `CLAUDE.md`) live OUTSIDE the vault
so the vault stays pure notes.

## Projects

- [[01-Project/Project Overview]] — what ECDAT is.
- [[01-Project/Requirements]] — SIH26164 requirements, MVP vs future.
- [[01-Project/Roadmap]] — Phase 0–10.

## Architecture

- [[02-Architecture/System Architecture]] · [[02-Architecture/Web App Architecture]]
- [[02-Architecture/CLI Agent Architecture]] · [[02-Architecture/Memory Architecture]]
- [[02-Architecture/Agent Integrations]]

## Rules

1. One fact lives in one note; link, don't duplicate.
2. Only persist future-value knowledge (decisions, discoveries, conventions, plans, milestones).
   Never raw prompts, transcripts, logs, or transient errors.
3. Every scanner-related note must distinguish REAL (SourceScanner) from MOCK findings.
4. Task notes go in `05-Tasks/`; session logs in `07-Sessions/` (dated, brief).
