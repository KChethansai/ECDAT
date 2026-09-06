# Freeze record — `phase-7-freeze` (commit e890ad1, pushed to origin main)

## Frozen state
- Backend 23 passed · CLI 22 passed · Vite build green · `compileall` clean.
- CLI and API scans byte-identical on fixtures (15/15 finding IDs).
- Mocks labeled in code/CBOM/GUI; Mosca framed as heuristic; no secrets in any output.
- Lone freeze fix: mock-scanner docstring scope wording (no behavior change).

## Known carry-forwards (do not regress)
1. Dashboard states code-reviewed only — needs one human visual click-through.
2. Quoted `"x.key"` fires as KEYFILE; unquoted bare filenames missed (documented).
3. Scan-session notes accumulate in `07-Sessions/Scans/` (bounded, harmless).

## Thaw rule
Next phase works on top of tag `phase-7-freeze`. If it breaks, `git reset --hard phase-7-freeze`.
