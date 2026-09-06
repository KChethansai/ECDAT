# ECDAT web-app (SIH26164 product foundation)

Modular monolith: Vite React GUI → FastAPI → scanner pipeline → CBOM JSON. No database.

```text
frontend/          # Vite + React (npm run dev, proxied /scans /reports /health)
backend/
  app/
    models.py      # CryptoFinding — the single normalized handoff
    scanner/
      source_scanner.py   # REAL source/config discovery (is_mock=False)
      mocks.py            # Binary/Container/Library/HSM/Cloud — same interface, is_mock=True
    risk.py        # Mosca inequality + severity
    recommend.py   # PQC/hybrid table
    cbom.py        # standardized JSON report (mock findings badged)
    main.py        # GET /health, POST /scans, GET /reports/{id}
  samples/vuln_sample/    # intentionally vulnerable fixture
  tests/                  # pytest pipeline + API tests
docs/              # product notes
```

## Run

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload   # :8000
cd ../frontend && npm install && npm run dev  # :5173 (proxied to :8000)
curl -X POST localhost:8000/scans -H 'Content-Type: application/json' \
  -d '{"target":"sample","scanners":["source"]}'
```

Reports are in-memory (restart clears; re-POST). `mockWarning` + MOCK badges appear
whenever mock scanners contribute. Never present MOCK rows as discovery.
