# ECDAT — SIH26164 Master Workspace

**Problem:** SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT), NTRO.
A CBOM analytics tool: scan source repos / binaries / libraries / container images →
quantum-risk assessment (Mosca) → classification → PQC/hybrid recommendations →
standardized reports + interactive GUI.

## Layout

```text
tools/                     # external references only (never imported by ECDAT code)
├── ponytail/              # DietrichGebert/ponytail (workflow reference)
├── get-shit-done/         # open-gsd/gsd-core (planning reference; upstream renamed)
├── everything-claude-code/# affaan-m/ECC (patterns reference)
└── fullstack-agent/       # jaredrhod/fullstack-agent, AGPL — independent optional tooling
obsidian-vault/            # authoritative persistent AI/project memory (Markdown only)
sih26164/
├── cli-agent/             # developer-facing multi-agent orchestration (own git repo, Python stdlib)
└── web-app/               # SIH product (own git repo, React/Vite + FastAPI)
```

> The Obsidian Vault is the authoritative persistent AI/project memory.

## Memory rule

- `obsidian-vault/` → persistent AI/project knowledge (Markdown).
- `git` → source + history.
- App DB → runtime/domain data only (no DB in MVP; none exists).
- Never store agent/project memory in a database, vector DB, or hidden JSON store.

## Quick start

```bash
# CLI agent (Python 3.10+, no dependencies)
cd sih26164/cli-agent
python -m agent status
python -m agent memory set demo.key "hello vault"
python -m agent memory get demo.key

# Web app backend (FastAPI)
cd ../web-app/backend
pip install -r requirements.txt
uvicorn app.main:app --reload  # GET /health, POST /scans, GET /reports/{id}

# Web app frontend
cd ../frontend
npm install && npm run dev
```

## Docs

- `sih26164/cli-agent/README.md` + `AGENTS.md` — CLI usage, adapters, memory.
- `sih26164/web-app/README.md` + `docs/` — product, scanner pipeline, API.
- `obsidian-vault/` — durable knowledge (human-readable, Obsidian-compatible).
- `docs/DEMO.md` (in cli-agent) — two-session persistent-memory demo.
- `TOOLS.md` — external tooling verification report.
