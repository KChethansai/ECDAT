# Project Overview

**SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)** · NTRO ·
Blockchain & Cybersecurity · Software.

Transitioning to post-quantum cryptography needs preparedness: the critical first step is
**discovery and inventory of cryptographic artefacts**, then quantum-risk assessment
(Mosca's inequality), classification, and PQC/hybrid migration recommendations.

## Deliverables (per PS)

Comprehensive CBOM analytics tool scanning **source repos, binaries, libraries, container images**;
standardized reports (versions/modes); **interactive GUI** to visualize scans, risks, results.

## Foundation scope (this repo state)

- `sih26164/cli-agent/` — orchestration CLI + Obsidian memory + provider-neutral adapters.
- `sih26164/web-app/` — FastAPI + Vite foundation; REAL `SourceScanner`, mock
  Binary/Container/Library/HSM/Cloud scanners behind the same `CryptoFinding` interface.
- `obsidian-vault/` — this memory layer. See [[VAULT-INDEX]].
