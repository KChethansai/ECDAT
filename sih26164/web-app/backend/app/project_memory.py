"""ECDAT-native offline project memory (stdlib only, no network, no AI, no DB).

One shared layer for the Web App side and the CLI: Markdown records written
directly into the user's local Obsidian vault filesystem. Obsidian itself is
only a viewer — plain files work with networking disabled and with Obsidian
absent. Product scanning never touches this module at runtime.

Layout follows the existing SIH vault (00-Inbox … 08-Reference); setup creates
only missing pieces and never overwrites user notes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import date
from pathlib import Path

MEMORY_SCHEMA_VERSION = 1
ENV_VAR = "OBSIDIAN_VAULT_PATH"
CONFIG_REL = Path("ecdat") / "vault"  # under the platform config dir
VAULT_LEAF = Path("Documents") / "Vaults" / "SIH"
MAX_NOTE_BYTES = 1_000_000

# Existing SIH sections (authoritative order); ECDAT records live inside them.
SECTIONS = ("00-Inbox", "01-Project", "02-Architecture", "03-Features",
            "04-Agents", "05-Tasks", "06-Research", "07-Sessions", "08-Reference")

# 03-Features does not exist yet in this vault; every other section does.
OPTIONAL_SECTIONS = {"03-Features"}

# Never persisted, even inside notes (values redacted, filenames refused).
SECRET_FILES = (".env", ".pem", ".key", "id_rsa", "id_ed25519", "credentials",
                "secrets", "token", "cookie")
SECRET_LINE_RE = re.compile(
    r"(?i)\b(api[_-]?key|password|passwd|secret|token|private[_-]?key|auth|cookie"
    r"|session[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S+")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    """Filesystem-safe note slug (deterministic, lowercase, dashed)."""
    return SLUG_RE.sub("-", text.strip().lower()).strip("-")[:80].strip("-") or "note"


# -- vault path resolution ----------------------------------------------------
# Priority: explicit arg > deployment config file > env var > user-local
# default. The developer path is NEVER a fallback: another user resolves to
# their own home directory.

def config_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / CONFIG_REL


def user_default_vault() -> Path:
    return Path.home() / VAULT_LEAF


def resolve_vault_path(explicit: str | None = None,
                       env: dict | None = None) -> Path:
    """Single authoritative resolver. Never raises for missing dirs."""
    if explicit:
        return Path(explicit).expanduser()
    cfg = config_file()
    if cfg.is_file():
        try:
            vault = json.loads(cfg.read_text(encoding="utf-8")).get("vault", "")
            if vault:
                return Path(vault).expanduser()
        except (ValueError, OSError, UnicodeError):
            pass
    env = os.environ if env is None else env
    if env.get(ENV_VAR):
        return Path(env[ENV_VAR]).expanduser()
    return user_default_vault()


# -- safe filesystem writes (vault jail, no symlinks out) -----------------------

def safe_join(vault: Path, relpath: str) -> Path:
    """Join + validate: relative .md path that resolves inside vault."""
    raw = (relpath or "").strip()
    if not raw or raw.startswith((".", "/")) or ".." in Path(raw).parts:
        raise ValueError(f"unsafe note path: {relpath!r}")
    raw = raw.strip("/")
    if not raw or ".." in Path(raw).parts:
        raise ValueError(f"unsafe note path: {relpath!r}")
    if not raw.endswith(".md"):
        raw += ".md"
    root = vault.expanduser().resolve()
    target = (root / raw).resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"path escapes vault: {relpath!r}")
    if target.is_symlink() or any(p.is_symlink() for p in target.parents
                                  if root in p.parents or p == root):
        raise ValueError(f"symlink in vault path: {relpath!r}")
    return target


def redact(text: str) -> str:
    """Redact secret assignments + key blocks. Values never survive."""
    out = SECRET_LINE_RE.sub("[REDACTED: sensitive configuration omitted]", text)
    out = PRIVATE_KEY_RE.sub("[REDACTED: private key omitted]", out)
    return out


def refuse_secret_file(relpath: str) -> None:
    low = relpath.lower()
    if any(token in low for token in SECRET_FILES):
        raise ValueError(f"refusing sensitive filename: {relpath!r}")


def sync_note(vault: Path, relpath: str, content: str,
              overwrite: bool = False) -> str:
    """Idempotent write: identical content is a no-op; historical notes are
    never overwritten unless overwrite=True. Returns created|unchanged|updated."""
    refuse_secret_file(relpath)
    body = redact(content)
    if len(body.encode("utf-8")) > MAX_NOTE_BYTES:
        raise ValueError("note too large")
    target = safe_join(vault, relpath)
    if target.exists():
        if target.read_text(encoding="utf-8", errors="replace") == body:
            return "unchanged"
        if not overwrite:
            raise FileExistsError(f"historical note exists (not overwritten): {relpath!r}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return "updated" if target.exists() and overwrite else "created"


# -- local git history (fixed argv, timeout, no shell, no remote) ----------------

def _git(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "--no-optional-locks", *args],
            capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"git unavailable: {type(exc).__name__}")
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed")
    return proc.stdout.strip()


def git_state(repo: Path) -> dict:
    """Branch, commit, short status, recent subjects. Read-only, local only."""
    try:
        return {"branch": _git(repo, "branch", "--show-current") or "(detached)",
                "commit": _git(repo, "rev-parse", "--short", "HEAD"),
                "dirty": bool(_git(repo, "status", "--short")),
                "recent": _git(repo, "log", "--oneline", "-8").splitlines()}
    except RuntimeError as exc:
        return {"error": str(exc)}


# -- deterministic record builders (pure functions; caller supplies date) --------

def frontmatter(kind: str, title: str, day: str, source: str,
                status: str = "completed") -> str:
    return (f"---\nproject: ECDAT\ntype: {kind}\ndate: {day}\n"
            f"source: {source}\nstatus: {status}\n"
            f"memory_schema_version: {MEMORY_SCHEMA_VERSION}\n---\n")


def session_note(title: str, day: str, source: str, objective: str = "",
                 context: str = "", work: str = "", files: str = "",
                 validation: str = "", git: str = "", decisions: str = "",
                 observations: str = "", next_step: str = "") -> tuple[str, str]:
    name = f"07-Sessions/{day}__session__{slug(title)}.md"
    body = (frontmatter("session", title, day, source)
            + f"# Session — {title}\n\n## Objective\n{objective}\n\n"
            + f"## Context\n{context}\n\n## Work Performed\n{work}\n\n"
            + f"## Files Changed\n{files}\n\n## Validation\n{validation}\n\n"
            + f"## Git State\n{git}\n\n## Decisions\n{decisions}\n\n"
            + f"## Observations\n{observations}\n\n## Next Step\n{next_step}\n")
    return name, body


def feature_note(name: str, day: str, purpose: str = "", architecture: str = "",
                 files: str = "", status: str = "implemented") -> tuple[str, str]:
    rel = f"03-Features/feature__{slug(name)}.md"
    body = (frontmatter("feature", name, day, "shared", status)
            + f"# Feature — {name}\n\n## Purpose\n{purpose}\n\n"
            + f"## Architecture\n{architecture}\n\n## Important Files\n{files}\n\n"
            + f"## Current Status\n{status}\n")
    return rel, body


def validation_note(title: str, day: str, source: str, scope: str = "",
                    method: str = "", result: str = "",
                    recommendation: str = "UNKNOWN") -> tuple[str, str]:
    rel = f"07-Sessions/{day}__validation__{slug(title)}.md"
    body = (frontmatter("validation", title, day, source)
            + f"# Validation — {title}\n\n## Scope\n{scope}\n\n"
            + f"## Method\n{method}\n\n## Result\n{result}\n\n"
            + f"## Release Recommendation\n{recommendation}\n")
    return rel, body


def audit_note(title: str, day: str, source: str, scope: str = "",
               findings: str = "", verdict: str = "UNKNOWN") -> tuple[str, str]:
    rel = f"08-Reference/{day}__audit__{slug(title)}.md"
    body = (frontmatter("audit", title, day, source)
            + f"# Audit — {title}\n\n## Scope\n{scope}\n\n"
            + f"## Findings\n{findings}\n\n## Verdict\n{verdict}\n")
    return rel, body


def commit_note(sha: str, day: str, subject: str, purpose: str = "",
                files: str = "", validation: str = "") -> tuple[str, str]:
    rel = f"07-Sessions/{day}__commit__{slug(sha[:12])}.md"
    body = (frontmatter("commit", subject, day, "shared")
            + f"# Commit — {subject}\n\nCommit: `{sha}`\n\n## Purpose\n{purpose}\n\n"
            + f"## Major Files\n{files}\n\n## Validation\n{validation}\n")
    return rel, body


def adr_note(number: int, title: str, day: str, context: str = "",
             decision: str = "", rationale: str = "",
             consequences: str = "") -> tuple[str, str]:
    rel = f"03-Decisions/ADR-{number:04d}-{slug(title)}.md"
    body = (frontmatter("adr", title, day, "shared")
            + f"# ADR-{number:04d} — {title}\n\n## Status\nAccepted\n\n"
            + f"## Context\n{context}\n\n## Decision\n{decision}\n\n"
            + f"## Rationale\n{rationale}\n\n## Consequences\n{consequences}\n")
    return rel, body


def state_note(day: str, branch: str, commit: str, release: str = "",
               features: str = "", validation: str = "",
               observations: str = "", next_work: str = "") -> tuple[str, str]:
    rel = "01-Project/ECDAT-current-state.md"
    body = (frontmatter("state", "ECDAT current state", day, "shared")
            + "# ECDAT Current State\n\n"
            + f"Branch: `{branch}` · Commit: `{commit}`\n\n"
            + f"## Release Status\n{release}\n\n## Implemented Features\n{features}\n\n"
            + f"## Validation Status\n{validation}\n\n## Observations\n{observations}\n\n"
            + f"## Next Planned Work\n{next_work}\n")
    return rel, body


# -- setup / deployment (offline; Obsidian only detected, never downloaded) -------

OBSIDIAN_BINARIES = ("obsidian",)
OBSIDIAN_PATHS = ("/usr/bin/obsidian", "/opt/Obsidian/obsidian",
                  "/snap/bin/obsidian")

INDEX_SKELETON = """# ECDAT Project Index

- [[01-Project/ECDAT-current-state]] — current snapshot (mutable).
- [[01-Project/Project Overview]] — what ECDAT is.
- [[01-Project/Roadmap]] — phases and milestones.
- [[03-Decisions]] — architectural decisions.
- [[07-Sessions]] — development sessions, commits, validation.
- [[08-Reference]] — audits and reference notes.
"""

STATE_SKELETON_DAY = "1970-01-01"


def detect_obsidian() -> dict:
    """Locate an existing Obsidian executable. Existence only — never launched,
    never downloaded. Returns {installed, path}."""
    found = shutil.which(OBSIDIAN_BINARIES[0])
    if not found:
        found = next((p for p in OBSIDIAN_PATHS if Path(p).is_file()), "")
    return {"installed": bool(found), "path": found or ""}


def setup_vault(vault: Path) -> dict:
    """Create missing sections + index/state skeletons. Idempotent: existing
    user notes are never touched. Returns per-item created|present."""
    root = vault.expanduser()
    report: dict = {"vault": str(root), "sections": {}, "notes": {}}
    for section in SECTIONS:
        target = root / section
        if target.is_dir():
            report["sections"][section] = "present"
        else:
            target.mkdir(parents=True, exist_ok=True)
            report["sections"][section] = "created"
    index = root / "08-Reference" / "ECDAT-project-index.md"
    if index.is_file():
        report["notes"]["index"] = "present"
    else:
        index.write_text(INDEX_SKELETON, encoding="utf-8")
        report["notes"]["index"] = "created"
    rel, body = state_note(STATE_SKELETON_DAY, "(unknown)", "(unknown)",
                           release="Not yet recorded — run `memory sync`.")
    state = root / rel
    if state.is_file():
        report["notes"]["state"] = "present"
    else:
        state.write_text(body, encoding="utf-8")
        report["notes"]["state"] = "created"
    return report


def write_deployment_config(vault: Path) -> Path:
    """Persist the chosen vault for this machine. Local file, no network."""
    cfg = config_file()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"vault": str(vault.expanduser()),
                               "memory_schema_version": MEMORY_SCHEMA_VERSION},
                              indent=2) + "\n", encoding="utf-8")
    return cfg


def setup_report(vault: Path, installer: str = "") -> dict:
    """Full first-run verdict without side effects beyond setup_vault/config.

    Obsidian missing + no local installer => status BLOCKED with the exact
    manual step (never claims an install that did not happen).
    """
    obs = detect_obsidian()
    vault_report = setup_vault(vault)
    cfg = write_deployment_config(vault)
    status, manual = "ready", ""
    installer_path = Path(installer).expanduser() if installer else None
    if installer_path and not installer_path.is_file():
        status, manual = "blocked", f"installer not found: {installer}"
    elif not obs["installed"]:
        status = "blocked" if not installer_path else "ready-manual-obsidian"
        if installer_path:
            manual = (f"Obsidian setup is manual: install {installer_path} "
                      f"(offline, user-approved), then re-run setup.")
        else:
            manual = ("Obsidian not detected. Supply a local installer via "
                      "--installer <path> (offline); ECDAT vault + config are ready.")
    return {"status": status, "obsidian": obs, "vault": vault_report,
            "config": str(cfg), "manual_step": manual,
            "memory_schema_version": MEMORY_SCHEMA_VERSION}


def today() -> str:
    return date.today().isoformat()
