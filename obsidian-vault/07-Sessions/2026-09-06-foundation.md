# Session 2026-09-06 — Foundation build

## Did

Cloned 4 tool refs; built dedicated vault (11 notes); Python-stdlib `cli-agent`
(memory provider, registry, 4 adapters, 8 commands, 14 tests incl. two-process proof);
FastAPI + Vite `web-app` (REAL SourceScanner, 5 mock scanners behind one interface,
Mosca risk, PQC table, CBOM, GUI with MOCK badges); 2 git repos; live API verified
(14 real findings on sample); all suites green.

## Learned

- `glittercowboy/get-shit-done` is archived → `open-gsd/gsd-core`; ECC repo renamed to `affaan-m/ECC`.
- System Python is PEP-668 managed → per-app `.venv` for pytest only (runtime stays dep-free for CLI).
- `cursor` binary is an agent shim (no IDE); adapters must not assume IDE presence.

## Next

Phase 5 integration (CLI `run` → real scan end-to-end), then binary/container depth (Phase 6).
