# ECDAT Security Knowledge Integration Report

- **Date:** 2026-09-06
- **Upstream:** `mukul975/Anthropic-Cybersecurity-Skills` @ `54a798831d2266a3ca61ce68a7acb80b81160d57`
- **License:** Apache-2.0 (verified in checked-out LICENSE + per-skill LICENSE files)
- **Outcome:** 32 of 818 skills integrated as a local advisory layer; deterministic engine unchanged.

## 1. Executive summary

ECDAT now pairs deterministic cryptographic discovery with a structured,
local-first security knowledge layer. Scanners, Mosca ordering,
recommendations, migration, and CBOM behave byte-identically (proven by
differential scans); findings additionally carry traceable analyst context
(skill, match strength, why-it-applies, guidance, verification checks,
framework mappings, provenance) in the drawer, on recommendation cards, and
in a subordinate knowledge explorer. No LLM, no network calls, no new
runtime dependencies, no evidence manufactured.

## 2. External repository analyzed

`mukul975/Anthropic-Cybersecurity-Skills` — 818 skills, agentskills.io
structure (`SKILL.md` + `references/` + `scripts/` + `assets/` + `LICENSE`
per skill), `index.json` v1.1.0, framework mappings (ATT&CK, NIST CSF 2.0,
ATLAS, D3FEND, AI RMF, F3), 45+ subdomain tags. Shallow-cloned to a scratch
directory outside the repo (deleted after audit); nothing copied blindly.

## 3. Repository revision/commit

`54a798831d2266a3ca61ce68a7acb80b81160d57` (main, 2026-09-06). Pinned in
`knowledge/provenance.py`, embedded in every report's `knowledgeContext`,
and recorded per skill in `docs/knowledge/skill-inventory.json`. Historical
reports stay explainable after future re-imports.

## 4. License

Apache-2.0 — confirmed via GitHub API metadata AND the checked-out LICENSE
file header AND per-skill LICENSE files. Integration uses transformative
normalized summaries (not verbatim copies, no scripts) with attribution +
provenance on every surface. Compliant; no conflicts.

## 5. Relevant domains

cryptography (Tier-1 core); supply-chain, cloud, container, DevSecOps
(Tier-2, crypto-adjacent only: SBOM/signing/provenance, KMS/secrets,
image signing, secret scanning).

## 6. Selected skills

16 Tier-1: cryptographic-audit, pqc-migrate, pqc-perform, rsa-mgmt, aes-rest,
ed25519-sig, jwt-sign, mtls, e2ee-msg (ECDH narrow), tls13-config,
tls-assess, cert-lifecycle, ca-openssl, hsm-config, hsm-integrate,
envelope-kms. 16 Tier-2: sbom-gen, sca-snyk, sbom-vuln, dep-confusion,
typosquat, slsa-sigstore, sigstore-sign, code-sign, in-toto, cosign-image,
registry-images, gcp-binauthz, vault-secrets, gitleaks, secrets-cicd,
vault-dynamic. (IDs are the registry keys; source skill names in
`skill-inventory.json`.)

## 7. Excluded skills

~786, by category: offensive/red-team (exploits, phishing, C2, privesc,
malware, hash-cracking, container escape, attack simulation), forensics/IR/
SOC/threat-hunt workflows ECDAT never performs, generic compliance (CMMC,
SOC2, ISO) with no crypto content, network/endpoint/mobile/OT/fraud skills,
and crypto skills with no ECDAT detection surface (zero-knowledge proofs,
Nitro Enclaves, generic container hardening, etcd/K8s administration).

## 8. Selection rationale

A skill was integrated only if its guidance maps to something ECDAT
detects — an algorithm family, scanner, category, or usage — expressed as
explicit `applies` rules. Narrow-scope skills map narrowly (e2ee-msg to
ECDH only; typosquat to dependency findings only). When in doubt the skill
was excluded; the explorer plus report metadata make the boundary auditable.

## 9. Knowledge architecture

`backend/app/knowledge/`: `provenance.py` (pinned source constants),
`_crypto.py` + `_adjacent.py` (32 static entries), `registry.py`
(assembly + structural validation), `matcher.py` (deterministic allowlist
matching, HIGH=algorithm rule / MEDIUM=scanner-category context, cap 5),
`__init__.py` (`annotate_report`, additive-only). `pipeline.run_scan`
calls `annotate_report` on the built report. Frontend reads the embedded
`knowledge` / `knowledgeBase` / `recommendationContext` / `knowledgeContext`
keys; no new endpoints, no schema breaks (pure additions).

## 10. Finding mappings

Examples (full table is the registry): RSA → crypto-audit/rsa-mgmt/pqc
(HIGH); AES → aes-rest/envelope-kms (HIGH); MD5 → crypto-audit (HIGH, and
explicitly NOT pqc-migrate); TLS → tls13-config/tls-assess/mtls (HIGH);
HSM/PKCS#11 → hsm-config/hsm-integrate (HIGH); KMS → envelope-kms/
vault-secrets (HIGH); ENV-SECRET → gitleaks/secrets-cicd/vault-dynamic
(HIGH); dependency rows → sbom-gen/sca-snyk/dep-confusion/typosquat +
provenance set; container rows → cosign-image/registry-images/gcp-binauthz.
MEDIUM fallback ranks methodology tier first, then scanner specificity.

## 11. Recommendation integration

Deterministic direction strings are unchanged. Each distinct direction gains
`recommendationContext`: contributing skill ids + up to 4 distilled
considerations (migration/interop/lifecycle). Rec cards render an
"Analyst Context (advisory)" block with skill names; the deterministic
direction, path, and evidence stay primary.

## 12. UI integration

No redesign. Drawer gains a SECURITY CONTEXT section (match badges, why,
top guidance, framework mappings, provenance footer; hidden when no match).
Rec cards gain Analyst Context. New subordinate Knowledge Explorer lists
matched skills with finding counts and expandable guidance/verification/
provenance. OBSERVED EVIDENCE and SECURITY KNOWLEDGE are visually separated
and labeled everywhere.

## 13. Provenance

Per-skill `{repository, skill, commit, license}` in the registry, embedded
in reports, and rendered in drawer/explorer/export surfaces. External
content is never presented as ECDAT-authored.

## 14. Security review

- No skill script imported, executed, or copied (verified by grep: no
  exec/eval/subprocess/network/file primitives in `knowledge/`; the single
  `requests.` hit is the English word in "idempotent requests").
- Registry is static Python literals; matcher does no templating into any
  prompt (there is no LLM); no deserialization of external files at runtime.
- No prompt-injection patterns in registry content; no URLs executed
  (registry contains zero URLs).
- Filesystem jail, CORS, redaction, and target validation untouched and
  re-verified live (out-of-tree and `..` → 400; evil origin gets no ACAO).
- Nothing uploaded anywhere; no external API called; fully offline-capable.

## 15. License review

Apache-2.0 confirmed three ways (API, root LICENSE, per-skill LICENSE).
Use is transformative summary + attribution + provenance. No copyleft
contamination, no license text that must ship in-product beyond the
rendered attribution (present).

## 16. Tests

`backend/tests/test_knowledge.py` (6 tests): registry well-formedness +
pinning, mapping coverage (RSA/AES/TLS/HSM/KMS/PEM/dependency/ENV/MD5/
lockfile), negative matching + graceful degradation + display budget,
additive-only invariance on a real fixture scan, precision-fix guards.
Suite: **69/69 green** (63 pre-existing + 6 new). CLI suite (imports the
shared pipeline): **35/35 green**. Frontend `npm run build`: green.

## 17. Real-project validation

All six validation-report projects rescanned through the browser UI, plus
zero probe, error path, runtime-equivalent flows, drawer/explorer/empty
states, and console collection:

| Project | Findings | Explorer skills | Note |
|---|---|---|---|
| frontend-src | 0 | section absent (correct) | IconShield fix holds |
| backend-app | 318 (221 pre-existing + 97 registry self-scan) | 17 | self-scan documented below |
| frontend-full | 116 | 4 | integrity rows carry sbom context |
| samples | 72 | 26 | all scanner types contextualized |
| cli-agent | 18 | 8 | RSA/PQC context present |
| obsidian-vault | 53 | 12 | prose findings get audit context |

Drawer SECURITY CONTEXT (5 matches on RSA), explorer expansion with
guidance/verification/provenance, rec-card Analyst Context, 404 path, and
500px/390px-column checks all verified in headless Firefox with **zero JS
errors**. Deterministic before/after differential on identical trees:
severity/priority/counts/migration/roadmaps byte-identical apart from the
additive knowledge keys.

## 18. Before/after behavior

- Findings/evidence/severity/priority/counts: **unchanged** (differential
  proof in §17; annotation adds keys only).
- Risk/migration/CBOM logic: **unchanged** (no edits; risk never reads
  knowledge keys).
- New: per-finding `knowledge`, `knowledgeBasis: "deterministic +
  knowledge"`; `knowledgeBase` (matched skills only); `recommendationContext`;
  `knowledgeContext` (enabled, advisory note, pinned source).
- Precision fixes preserved: nShield∉IconShield, KEYSIZE reads silent,
  lockfile rows stay `dependency integrity metadata` (all re-tested in
  `test_knowledge.py`).
- Known self-scan property: the registry's own prose mentions algorithms,
  so scanning `backend/app` now includes 97 honest reference findings from
  `knowledge/*.py` (60 critical by the unchanged short-RSA-style rules).
  This is reference discovery working as designed — identical in kind to
  the engine's pattern tables matching themselves — and is documented here,
  not hidden. Evidence text makes the prose nature obvious.

## 19. Performance

`annotate_report` on the 15-finding fixture: **0.0005 s** (scan itself
0.004 s). Matching is dict lookups; registry is a module-level list; no
per-scan file parsing. UI round-trips unchanged (1.7–2.9 s incl. settle
waits). No virtualization or caching layer needed.

## 20. Limitations

- Static guidance pinned at import; upstream edits require re-import
  (procedure in `docs/knowledge/README.md`).
- Prose/reference findings (docs, pattern tables, this registry) score
  severity like code — the documented reference-semantics boundary.
- Framework mappings are contextual metadata, never compliance claims;
  no compliance scores are generated.
- Governance coverage is via migration/audit skills + CSF mappings; no
  standalone crypto-governance skill met the relevance bar.
- No LLM exists; any future one must consume this structured context and
  stay advisory-only.

## 21. Future work

- Re-import cadence for upstream skill updates (pinned-commit workflow).
- Optional semantic retrieval as a supplement to (never a replacement for)
  allowlist matching.
- Explicitly configured additional scan roots (allowlist-based) for broader
  local validation — jail stays as-is until then.

## 22. Final verdict

**PASS.** 32/32 relevant skills integrated with provenance; deterministic
engine, risk, migration, and CBOM provably unchanged; 69/69 backend +
35/35 CLI tests green; frontend builds; six real projects validated live
with zero console errors; security and license audits clean.
