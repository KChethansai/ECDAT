# Phase 5 — integrated CLI scan workflow

- CLI `agent scan <target>` validates a workspace-contained, non-symlink source target and calls the web backend shared `app.pipeline.run_scan` domain path.
- API and CLI share SourceScanner → CryptoFinding → Mosca risk → recommendation → CBOM behavior; source scanning remains deterministic and provider-independent.
- Scan context is bounded to the top five relevant Vault notes. Durable summaries are written under `07-Sessions/Scans/` without evidence, key material, or full CBOM payloads.
- Verification: CLI 21 passed, backend 12 passed, frontend build passed; the vulnerable fixture produced 15 real / 0 mock findings and a critical RSA-1024 recommendation.
