"""CLI smoke tests via in-process main() with an isolated vault env."""

import json
import os

import agent.cli as cli
from agent.config import WORKSPACE_ROOT


def _run(monkeypatch, tmp_path, *argv):
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path / "v"))
    return cli.main(["--vault", str(tmp_path / "v"), *argv])


def test_init_status_agents(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, "init") == 0
    assert _run(monkeypatch, tmp_path, "status") == 0
    assert _run(monkeypatch, tmp_path, "agents") == 0
    out = capsys.readouterr().out
    assert "vault" in out and "codex" in out


def test_memory_set_get_cycle(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, "init") == 0
    assert _run(monkeypatch, tmp_path, "memory", "set", "s1.key", "hello") == 0
    assert _run(monkeypatch, tmp_path, "memory", "get", "s1.key") == 0
    assert "hello" in capsys.readouterr().out


def test_context_and_plan(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, "init") == 0
    assert _run(monkeypatch, tmp_path, "memory", "write", "06-Research/N", "mosca notes") == 0
    assert _run(monkeypatch, tmp_path, "context", "mosca task") == 0
    assert _run(monkeypatch, tmp_path, "plan", "write docs") == 0
    assert "05-Tasks" in capsys.readouterr().out


def test_scan_uses_shared_pipeline_and_persists_bounded_summary(monkeypatch, tmp_path, capsys):
    vault = tmp_path / "v"
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "init") == 0
    assert _run(monkeypatch, tmp_path, "memory", "write", "02-Architecture/Scan Context",
                "ECDAT source scans use Mosca risk and CBOM reports.") == 0
    capsys.readouterr()

    assert _run(monkeypatch, tmp_path, "scan", str(sample)) == 0
    result = json.loads(capsys.readouterr().out)
    report = result["report"]
    assert "02-Architecture/Scan Context.md" in result["contextNotes"]
    assert 0 < result["contextChars"] <= 4000
    assert report["metadata"]["contextProvenance"] == {
        "available": True, "notes": 1, "chars": result["contextChars"], "maxChars": 4000}
    assert report["summary"]["real"] > 0 and report["summary"]["mock"] == 0
    assert any(row["algorithm"] == "RSA" and row["severity"] == "critical"
               and "ML-KEM" in row["recommendation"]["recommend"]
               for row in report["components"])
    assert report["bomFormat"] == "ECDAT-CBOM"

    summaries = list(vault.glob("07-Sessions/Scans/*.md"))
    assert len(summaries) == 1
    summary = summaries[0].read_text()
    assert "RSA" in summary and "critical" in summary
    assert "Bounded orchestration context:" in summary
    assert "demo-input" not in summary and "BEGIN CERTIFICATE" not in summary


def test_scan_rejects_targets_outside_workspace(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, "scan", "../outside") == 2
    assert "unsafe scan target" in capsys.readouterr().err


def test_scan_summary_output(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "scan", str(sample), "--summary") == 0
    output = capsys.readouterr().out
    assert "ECDAT source scan complete" in output
    assert "severity:" in output and "priority:" in output
    assert "durable summary:" in output and "CBOM-style report:" in output


def test_scan_rejects_invalid_risk_horizons(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "scan", str(sample), "--data-years", "-1") == 2
    assert "between 0 and 100" in capsys.readouterr().err
