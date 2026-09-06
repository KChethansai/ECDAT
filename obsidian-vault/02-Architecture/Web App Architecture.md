# Web App Architecture (modular monolith)

```text
Vite React GUI → FastAPI (/health, POST /scans, GET /reports/{id})
→ scanner/ (SourceScanner REAL; Binary/Container/Library/HSM/Cloud MOCK)
→ models.CryptoFinding → risk.py (Mosca) → recommend.py (PQC table) → cbom.py (JSON)
```

No database. Reports are rebuilt deterministically from scan inputs (mock runs seeded).
Key material is never returned — metadata only.
