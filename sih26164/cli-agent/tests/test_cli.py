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
    assert "ECDAT scan complete" in output
    assert "severity:" in output and "priority:" in output
    assert "migration:" in output and "MIGRATION_REQUIRED" in output
    assert "durable summary:" in output and "CBOM-style report:" in output


def test_scan_rejects_invalid_risk_horizons(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "scan", str(sample), "--data-years", "-1") == 2
    assert "between 0 and 100" in capsys.readouterr().err


def test_scan_runtime_requires_explicit_opt_in(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "scan", str(sample)) == 0
    static_only = json.loads(capsys.readouterr().out)["report"]
    assert [c for c in static_only["components"] if c["scanner"] == "runtime"] == []
    assert _run(monkeypatch, tmp_path, "scan", str(sample), "--runtime", "--summary") == 0
    output = capsys.readouterr().out
    assert "runtime: 6 observations (controlled opt-in probe)" in output


def test_scan_discovers_binary_provenance(monkeypatch, tmp_path, capsys):
    binary = (WORKSPACE_ROOT / "sih26164" / "web-app" / "backend"
              / "samples" / "binaries" / "openssl-linked-demo.bin")
    assert _run(monkeypatch, tmp_path, "scan", str(binary)) == 0
    report = json.loads(capsys.readouterr().out)["report"]
    rows = [row for row in report["components"] if row["scanner"] == "binary"]
    assert rows and all(row["is_mock"] is False for row in rows)
    assert any(row["library"] == "libcrypto.so.3" and row["priority"] in ("P0", "P1", "P2", "P3")
               and "ML-KEM" not in row["recommendation"]["recommend"]  # library: honest guidance
               for row in rows)
    assert report["summary"]["mock"] == 0


def test_scan_covers_all_real_scanner_provenances(monkeypatch, tmp_path, capsys):
    samples = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples"
    assert _run(monkeypatch, tmp_path, "scan", str(samples)) == 0
    report = json.loads(capsys.readouterr().out)["report"]
    assert {"source", "binary", "container", "dependency", "hsm", "cloud"} <= {
        row["scanner"] for row in report["components"]}
    assert report["summary"]["mock"] == 0
