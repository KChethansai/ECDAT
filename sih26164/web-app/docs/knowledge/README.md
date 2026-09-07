# ECDAT Security Knowledge Layer

Advisory, local-first, deterministic security context around ECDAT's
deterministic discovery engine. The engine answers *"what cryptographic
evidence exists?"*; this layer answers *"what does it mean, what should an
analyst check, and what migration guidance applies?"* — without ever
manufacturing evidence.

## What it is

- A static registry of **32 normalized skills** (`backend/app/knowledge/`):
  16 Tier-1 cryptography + 16 Tier-2 adjacent (supply-chain, cloud, container,
  DevSecOps). Full list with provenance: `skill-inventory.json`.
- Deterministic allowlist matching on algorithm, scanner, category, usage
  (`matcher.py`). No fuzzy/semantic retrieval, no LLM, no network.
- Report enrichment only: per-finding `knowledge` matches, per-direction
  `recommendationContext`, matched-skill `knowledgeBase`, and `knowledgeContext`
  metadata. Severity, priority, counts, migration, and CBOM inventory are
  untouched by construction (risk never reads these keys).

## What it is not

- Not a scanner, not a risk engine, not a chatbot, not a pentest framework.
- Skill automation scripts from the upstream repository were never imported,
  executed, or copied. Only published guidance was distilled into
  ECDAT-authored summaries.
- Framework mappings (NIST CSF, MITRE ATT&CK) are contextual metadata on
  knowledge cards. They are **not** compliance claims about ECDAT or the
  scanned project. ECDAT generates no compliance scores.

## Confidence model (three separate things)

- **Evidence confidence**: from the scanner (HIGH/MEDIUM/LOW evidence strength).
- **Knowledge match**: HIGH (algorithm-level rule) / MEDIUM (scanner/category
  context rule). Rule depth, not a model score. Capped at 5 per finding.
- **Recommendation basis**: always `deterministic + knowledge`.

## Provenance

Every entry carries `{repository, skill, commit, license}`:

- repository: `mukul975/Anthropic-Cybersecurity-Skills`
- commit: `54a798831d2266a3ca61ce68a7acb80b81160d57`
- license: `Apache-2.0` (verified in the checked-out LICENSE file;
  per-skill LICENSE files agree)

External content is never presented as ECDAT-authored; the UI shows the
source repo, short commit, and license on every knowledge surface.

## Selection rationale (why these 32 of 818)

- **Included:** skills whose guidance maps to something ECDAT actually
  detects (algorithms, scanners, categories, usages in the registry's
  `applies` blocks).
- **Excluded (~786):** offensive/red-team skills (exploits, phishing, C2,
  privesc, malware, ransomware tooling), forensics/IR/SOC workflows ECDAT
  never performs, generic compliance frameworks with no crypto content,
  network/endpoint/mobile/OT skills outside the crypto-inventory mission,
  and skills with no ECDAT detection surface (e.g. zero-knowledge proofs,
  Nitro Enclaves, generic container hardening).

## Updating the source

1. Check out a new upstream commit; record its SHA.
2. Re-run the relevance screen; add entries to
   `backend/app/knowledge/_crypto.py` / `_adjacent.py` with `applies` rules.
3. Update `provenance.py` (`SOURCE_COMMIT`, `IMPORTED_AT`) and regenerate
   `skill-inventory.json` from the registry.
4. Run `pytest -q` (mapping/invariance tests pin behavior) and revalidate
   against the six real projects. Historical reports keep their embedded
   `knowledgeContext.source`, so old reports stay explainable.

## Limitations

- Guidance is static text pinned at import time; it does not track upstream
  edits until re-imported.
- Reference-based discovery means prose mentions (docs, pattern tables, and
  this knowledge base itself) produce reference findings by design — read
  the evidence, not just the count.
- No LLM integration exists; if one is added later it must consume this
  layer's structured context and remain advisory-only.
