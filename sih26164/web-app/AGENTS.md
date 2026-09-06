# AGENTS.md — web-app

- `CryptoFinding` (`backend/app/models.py`) is the only handoff between scanners and
  risk/rec/CBOM. New scanners implement `Scanner.scan()` and return it.
- REAL vs MOCK is load-bearing: `is_mock=True` must surface in CBOM (`mockWarning`)
  and GUI (MOCK badge). Tests assert this.
- No database. No key-material dumps (evidence truncated to 160 chars).
- Backend checks: `python -m pytest -q` from `backend/`. Frontend: `npm run build`.
