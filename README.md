# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

**Problem (SIH26164, NTRO):** discover every cryptographic asset in an
enterprise codebase — source, binaries, libraries, container images — assess
quantum risk, and produce actionable PQC migration plans.

**Pipeline:** scan targets → crypto discovery → quantum-risk assessment
(Mosca's inequality) → classification → PQC/hybrid recommendations →
migration planning → standardized CBOM reports + interactive GUI.

## Features

- **Cryptographic discovery** — static scanners for source/config, binaries
  (ELF/PE/Mach-O), containers (image archives, OCI layouts, Dockerfiles),
  dependencies (manifests + lockfiles), HSM references (PKCS#11, static only),
  cloud KMS references (identifiers only), plus an explicit opt-in runtime
  probe (bundled fixture, timeout + isolation — target code never executed).
- **Quantum risk + recommendations** — Mosca exposure scoring, severity tiers,
  PQC/hybrid migration table, inventory, correlation, migration work items
  with status/roadmap, CycloneDX-style CBOM JSON, SARIF 2.1.0 export.
- **Code Intelligence** — deterministic static analysis (dead code,
  duplication, complexity, efficiency, dependencies, structure) emitting
  `CodeFinding`s (engineering impact, never crypto severity), ranked, with
  remediation options, constraints, deterministic plans (`plan.json`/`plan.md`
  + agent prompt), and before/after verification.
- **Active Validation** — opt-in loopback-first TLS/HTTP observation with
  budgets, dry-run, redaction, correlation (`observed` vs `confirmed`),
  re-validation; non-loopback requires explicit acknowledgement.
- **GitHub source acquisition** — public repos via validated URL → ref/SHA
  resolution → bounded download → hostile-tar-safe extraction → isolated
  workspace → the same pipeline. Commit SHA is the scan identity; findings
  stay comparable across commits (delta: NEW/RESOLVED/UNCHANGED/CHANGED/
  REGRESSION), history, fp-keyed triage, scan profiles
  (`quick|crypto|codebase|full|full-validation`).
- **Codebase knowledge graph** — one deterministic relationship model
  (file/symbol/import/call/test/config/API/crypto/finding nodes with
  evidence + confidence) projected as component graph, per-finding
  blast radius (affected surface with traceability), and Obsidian Canvas
  JSON + linked Markdown notes; feeds dynamic remediation planning and
  plan-reference validation. Stdlib only, offline, no ML/embeddings/databases.
- **Project memory** — one shared offline layer (CLI + backend) writing
  Markdown session/validation/audit/commit/state records into the user's
  local Obsidian vault (`OBSIDIAN_VAULT_PATH`, else user-local
  `~/Documents/Vaults/SIH`); product runs fully without Obsidian.
- **Interfaces** — FastAPI backend (`/health`, `/scans`, reports, analysis,
  plans, validation, SARIF, history/delta/triage), Vite+React workstation GUI
  (local/GitHub sources, profiles, findings, drawers, remediation, history,
  compare, exports), and a zero-dependency Python CLI that orchestrates
  external coding agents without embedding an LLM.

## Stack

- Backend: Python 3.10+ stdlib (AST, `tarfile`, `ssl`, `http.client`) +
  FastAPI + uvicorn (serving only); pytest + httpx (tests only).
- Frontend: React 18 + Vite (no UI framework; no runtime API keys).
- CLI: Python stdlib only, zero runtime dependencies.
- Storage: local Markdown (Obsidian vault) + Git; no database, no cloud,
  no network required except user-requested GitHub acquisition / probes.

## Implementation methods

- **Deterministic-first:** stable finding/graph IDs, sorted outputs,
  byte-identical reports for identical inputs (timestamps excluded);
  nondeterminism is treated as a defect.
- **Static-only analysis:** repositories are data, never executed; no
  installs, builds, scripts, hooks, or actions run automatically.
- **Evidence + confidence:** every relationship, recommendation, and plan
  entry carries evidence; heuristics are labeled MEDIUM/LOW and never
  presented as confirmed fact; insufficient evidence says UNKNOWN.
- **Safety by construction:** path jails, symlink refusal, archive caps,
  SSRF/redirect controls, secret redaction, payload caps, loopback-first
  probing, explicit opt-ins; vault failures degrade, never crash the product.
- **Separation of concerns:** `CryptoFinding` (security) vs `CodeFinding`
  (engineering) never mix; triage/planning are presentation-only and never
  mutate evidence, risk, or CBOM.

## Layout

```text
obsidian-vault/            # frozen Phase 1–8 reference copy (canonical vault lives at ~/Documents/Vaults/SIH)
sih26164/
├── cli-agent/             # provider-neutral orchestration CLI (stdlib, zero runtime deps)
└── web-app/
    ├── backend/app/       # scanners, risk, CBOM, code intelligence, validation,
    │                      #   sources (GitHub), knowledge, codegraph, project_memory, API
    ├── frontend/src/      # React workstation GUI
    └── docs/              # product + architecture documentation
```

## Quick start

```bash
# CLI agent (Python 3.10+, no runtime dependencies)
cd sih26164/cli-agent
python scripts/agent status
python scripts/agent scan ../web-app/backend/samples --summary
python scripts/agent explain ../web-app/backend/samples/vuln_sample --ask "what should we migrate first"
python scripts/agent graph status ../web-app/backend/app
python scripts/agent memory status

# Web app backend (FastAPI)
cd ../web-app/backend
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload  # :8000 — GET /health, POST /scans, GET /reports/{id}

# Web app frontend
cd ../frontend
npm install && npm run dev  # :5173, API proxied to :8000
```

Explicit opt-ins: `agent scan <target> --runtime`, validation targets,
non-loopback acknowledgement. Public GitHub repos scan statically:
`agent scan ignored --github https://github.com/owner/repo --ref main --profile full --summary`,
the web UI source picker, or `POST /scans` with
`{"source": {"type": "github", "url": "...", "ref": "main"}, "profile": "full"}`.

## Docs

- `sih26164/web-app/README.md` + `docs/` — product, pipeline, API, architecture
  (GitHub scanning, Active Validation, Code Intelligence, remediation, knowledge graph).
- `sih26164/cli-agent/README.md` + `AGENTS.md` — CLI usage, adapters, memory, graph.
- `~/Documents/Vaults/SIH` — durable project knowledge (human-readable, Obsidian-compatible).
