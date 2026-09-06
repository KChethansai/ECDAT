# ECDAT demo runbook (manual acceptance pass)

Prerequisites: backend venv installed, frontend `npm install` done.
All fixtures under `backend/samples/` are safe (inert binaries, redacted configs).

```bash
cd sih26164/web-app/backend
.venv/bin/uvicorn app.main:app --port 8000 &
cd ../frontend && npm run dev   # :5173
```

1. **Start ECDAT** — open http://localhost:5173; backend `/health` shows scanners + probe.
2. **Run a scan** — target `sample` (or `sih26164/web-app/backend/samples`), Run scan.
3. **Multi-source discovery** — Sources line lists source, binary, container,
   dependency, hsm, cloud; findings table Src column shows per-row provenance.
4. **Inventory** — UNIFIED INVENTORY table: families, scanners, artifacts, strength.
5. **High-priority findings** — metrics + FIX FIRST panel; filter Priority=P0.
6. **Finding details** — click an algorithm: evidence, strength, status, related links.
7. **Relationships** — RELATIONSHIPS section per family + runtime observed/not-observed
   note (non-observation is never proof of absence).
8. **Migration roadmap** — MIGRATION WORKSPACE buckets → work item → direction/unknowns.
9. **CBOM-style output** — Download CBOM-style JSON; verify it matches the screen.
10. **Controlled runtime** — tick `runtime probe`, re-scan: 6 observations, correlation
    line on SHA rows, `runtimeProvenance` in JSON. Default scans never execute.
11. **AI explanation** — ANALYST SUMMARY panel + per-finding deterministic explanation;
    CLI: `agent explain <target> --ask "..."` (offline; `--agent` for provider Q&A).
12. **Obsidian persistence** — `agent scan <target> --summary` prints the durable
    vault note path in `~/Documents/Vaults/SIH/07-Sessions/Scans/`.
13. **Clean errors** — scan `/does/not/exist` (API 404 / CLI exit 2 for unsafe)
    and an unknown report id (API 404); UI shows the error state, no traceback,
    no fake data.

Honesty checklist for the demo: mocks say MOCK (none remain by default); Mosca is a
heuristic; static presence is not runtime use; no live cloud/HSM enumeration.
