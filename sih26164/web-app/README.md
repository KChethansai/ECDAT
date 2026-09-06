# ECDAT web-app (SIH26164 product foundation)

Modular monolith: Vite React GUI → FastAPI → scanner pipeline → CBOM JSON. No database.

```text
frontend/          # Vite + React (npm run dev, proxied /scans /reports /health)
backend/
  app/
    models.py      # CryptoFinding — the single normalized handoff
    scanner/
      source_scanner.py   # REAL source/config discovery (is_mock=False)
      binary_scanner.py   # REAL static binary indicators: ELF/PE/Mach-O strings,
                          # library/symbol refs, embedded cert metadata (is_mock=False)
      container_scanner.py# REAL static container inspection: image archives, OCI
                          # layouts, Dockerfiles — streamed, never executed (is_mock=False)
      dependency_scanner.py # REAL manifest analysis: requirements/pyproject/
                          # package.json/lockfiles/pom.xml/Gradle/Cargo/go.mod (is_mock=False)
      mocks.py            # HSM/Cloud — same interface, is_mock=True
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
