"""Shared project-memory layer: resolver, records, git, security, setup.

All vault I/O targets tmp_path fixtures — never the developer vault.
"""

import json
import os

import pytest

from app import project_memory as pm


# -- resolver ---------------------------------------------------------------

def test_resolver_priority_and_user_default(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert pm.resolve_vault_path("/explicit/v", {}) == __import__("pathlib").Path("/explicit/v")
    assert pm.resolve_vault_path(None, {"OBSIDIAN_VAULT_PATH": "/from/env"}) \
        .as_posix() == "/from/env"
    assert pm.resolve_vault_path(None, {}) == home / "Documents" / "Vaults" / "SIH"


def test_resolver_deployment_config_beats_env(monkeypatch, tmp_path):
    cfg_home = tmp_path / "cfg"
    (cfg_home / "ecdat").mkdir(parents=True)
    (cfg_home / "ecdat" / "vault").write_text(json.dumps({"vault": "/from/config"}))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg_home))
    out = pm.resolve_vault_path(None, {"OBSIDIAN_VAULT_PATH": "/from/env"})
    assert out.as_posix() == "/from/config"


def test_resolver_broken_config_falls_through(monkeypatch, tmp_path):
    cfg_home = tmp_path / "cfg"
    (cfg_home / "ecdat").mkdir(parents=True)
    (cfg_home / "ecdat" / "vault").write_text("not json{")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg_home))
    assert pm.resolve_vault_path(None, {"OBSIDIAN_VAULT_PATH": "/e"}).as_posix() == "/e"


# -- safe paths + redaction ---------------------------------------------------

@pytest.mark.parametrize("bad", ["", "/abs.md", "../x.md", "a/../../b.md",
                                 ".hidden.md", ".."])
def test_unsafe_paths_rejected(tmp_path, bad):
    with pytest.raises(ValueError):
        pm.safe_join(tmp_path, bad)


def test_safe_join_appends_md_and_jails_symlink(tmp_path):
    assert pm.safe_join(tmp_path, "a/b").name == "b.md"
    outside = tmp_path.parent / "pm-outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        pm.safe_join(tmp_path, "link/x.md")


def test_redaction_and_secret_filenames(tmp_path):
    dirty = "api_key: sk-12345\npassword = hunter2\n-----BEGIN RSA PRIVATE KEY-----\nok"
    clean = pm.redact(dirty)
    assert "sk-12345" not in clean and "hunter2" not in clean
    assert "PRIVATE KEY-----" not in clean and "REDACTED" in clean
    with pytest.raises(ValueError):
        pm.sync_note(tmp_path, ".env", "x=1")
    rel, body = pm.session_note("t", "2026-09-07", "cli", context=dirty)
    assert pm.sync_note(tmp_path, rel, body) == "created"
    assert "sk-12345" not in (tmp_path / rel).read_text()


def test_sync_idempotent_and_historical_immutable(tmp_path):
    rel, body = pm.validation_note("v", "2026-09-07", "cli", result="ok")
    assert pm.sync_note(tmp_path, rel, body) == "created"
    assert pm.sync_note(tmp_path, rel, body) == "unchanged"
    with pytest.raises(FileExistsError):
        pm.sync_note(tmp_path, rel, body + "more")
    assert pm.sync_note(tmp_path, rel, body + "more", overwrite=True) == "updated"


# -- builders ------------------------------------------------------------------

def test_builders_deterministic_and_linked():
    a = pm.session_note("T", "2026-09-07", "cli", work="did x")
    b = pm.session_note("T", "2026-09-07", "cli", work="did x")
    assert a == b
    assert a[0].startswith("07-Sessions/") and "memory_schema_version: 1" in a[1]
    for rel, body in (pm.feature_note("F", "2026-09-07"),
                      pm.audit_note("A", "2026-09-07", "cli"),
                      pm.commit_note("abc123", "2026-09-07", "subj"),
                      pm.adr_note(7, "Title", "2026-09-07"),
                      pm.state_note("2026-09-07", "main", "abc")):
        assert rel.endswith(".md") and "memory_schema_version: 1" in body
    assert pm.slug("Hello, World!") == "hello-world"


# -- git (local only) ------------------------------------------------------------

def test_git_state_reads_repo():
    from pathlib import Path

    state = pm.git_state(Path(__file__).resolve().parents[3])
    assert state["commit"] and state["branch"] and isinstance(state["recent"], list)


def test_git_state_missing_repo(tmp_path):
    assert "error" in pm.git_state(tmp_path)


# -- setup / installer -------------------------------------------------------------

def test_setup_idempotent_and_never_overwrites(tmp_path):
    vault = tmp_path / "v"
    first = pm.setup_vault(vault)
    assert all(v == "created" for v in first["sections"].values())
    sentinel = vault / "01-Project" / "ECDAT-current-state.md"
    sentinel.write_text("mine")
    second = pm.setup_vault(vault)
    assert all(v == "present" for v in second["sections"].values())
    assert sentinel.read_text() == "mine"


def test_setup_report_offline_missing_obsidian(monkeypatch, tmp_path):
    monkeypatch.setattr(pm.shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(pm, "OBSIDIAN_PATHS", ())
    rep = pm.setup_report(tmp_path / "v")
    assert rep["status"] == "blocked" and rep["obsidian"] == {"installed": False, "path": ""}
    assert "manual" in rep["manual_step"].lower() or "--installer" in rep["manual_step"]
    assert "config" in rep and pm.config_file  # deployment config written
    again = pm.setup_report(tmp_path / "v")
    assert again["vault"]["sections"]["01-Project"] == "present"


def test_setup_report_bad_installer(tmp_path):
    rep = pm.setup_report(tmp_path / "v", installer="/nope.AppImage")
    assert rep["status"] == "blocked" and "not found" in rep["manual_step"]


def test_detect_obsidian_shape():
    obs = pm.detect_obsidian()
    assert set(obs) == {"installed", "path"} and isinstance(obs["installed"], bool)


# -- offline: memory module must not need the network -------------------------------

def test_no_network_imports():
    # Static proof for this module (sys.modules is suite-order-dependent).
    src = __import__("pathlib").Path(pm.__file__).read_text()
    for token in ("import requests", "import httpx", "import urllib", "urlopen",
                  "WebSocket", "telemetry", "import socket"):
        assert token not in src, token
