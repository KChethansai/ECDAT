# ADR-0003 — Real SourceScanner, mocks behind the same interface

Date: 2026-09-06 · Status: accepted.

MVP ships a REAL regex-based source/config scanner (algorithms, protocols, certs, key sizes,
library refs). Binary/Container/Library/HSM/Cloud scanners implement the same
`scan(target) -> list[CryptoFinding]` interface but return `is_mock=True` findings until real
connectors exist. GUI and CBOM must badge MOCK visibly.
