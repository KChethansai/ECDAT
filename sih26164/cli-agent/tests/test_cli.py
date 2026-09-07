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


def test_explain_offline_paths(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "explain", str(sample),
                "--ask", "what should we migrate first") == 0
    out = capsys.readouterr().out
    assert "# Analyst (migration)" in out and "## UNKNOWN" in out
    assert _run(monkeypatch, tmp_path, "explain", str(sample),
                "--finding", "missing-id") == 1
    assert "unknown finding id" in capsys.readouterr().err


def test_explain_provider_failure_is_clean(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "explain", str(sample), "--agent", "ghost") == 1
    err = capsys.readouterr().err
    assert "provider unavailable" in err or "unknown agent" in err


def test_unknown_options_rejected_not_swallowed(monkeypatch, tmp_path):
    with __import__("pytest").raises(SystemExit) as exc:
        _run(monkeypatch, tmp_path, "status", "--bogus")
    assert exc.value.code == 2


def test_run_unknown_agent_is_clean(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, "run", "--agent", "ghost",
                "--task", "hi", "--", "--help") == 1
    assert "unknown agent" in capsys.readouterr().err


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


def test_scan_validate_dry_run_and_validate_command(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "scan", str(sample), "--summary",
                "--validate", "--dry-run") == 0
    out = capsys.readouterr().out
    assert "validation:" in out and "[DRY RUN]" in out
    sarif_out = tmp_path / "out.sarif"
    assert _run(monkeypatch, tmp_path, "validate", str(sample), "--dry-run",
                "--sarif-out", str(sarif_out)) == 0
    assert "ECDAT validation complete [DRY RUN]" in capsys.readouterr().out
    doc = json.loads(sarif_out.read_text())
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "ECDAT"


def test_validate_fail_on_gates(monkeypatch, tmp_path, capsys):
    sample = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    # dry run produces no CONFIRMED results -> gate passes; critical findings exist -> gate fails
    assert _run(monkeypatch, tmp_path, "validate", str(sample), "--dry-run",
                "--fail-on", "confirmed") == 0
    capsys.readouterr()
    assert _run(monkeypatch, tmp_path, "validate", str(sample), "--dry-run",
                "--fail-on", "critical") == 1
    assert "gate:" in capsys.readouterr().out


def test_analyze_summary_and_remediate_verify_flow(monkeypatch, tmp_path, capsys):
    # Filesystem jail applies to analysis too: use a workspace-contained target.
    repo = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "app" / "code_analysis"
    assert _run(monkeypatch, tmp_path, "analyze", str(repo), "--dead-code",
                "--summary") == 0
    out = capsys.readouterr().out
    assert "ECDAT code analysis complete (deterministic, no AI)" in out
    analysis_file = tmp_path / "analysis.json"
    assert _run(monkeypatch, tmp_path, "analyze", str(repo),
                "--out", str(analysis_file)) == 0
    capsys.readouterr()
    analysis = json.loads(analysis_file.read_text())
    assert analysis["findings"], "analyzer self-scan should yield findings"
    target = analysis["findings"][0]
    plan_file = tmp_path / "plan.json"
    assert _run(monkeypatch, tmp_path, "remediate", "--analysis", str(analysis_file),
                "--finding", target["id"], "--option", "delete",
                "--constraint", "preserve-tests", "--out", str(plan_file)) == 0
    assert f"plan {json.loads(plan_file.read_text())['plan_id']} written" in capsys.readouterr().out
    assert _run(monkeypatch, tmp_path, "remediate", "--analysis", str(analysis_file),
                "--finding", target["id"], "--option", "nope") == 2
    capsys.readouterr()
    fixed = tmp_path / "fixed.json"
    fixed.write_text(json.dumps({"findings": []}))
    assert _run(monkeypatch, tmp_path, "verify-fix", "--before", str(analysis_file),
                "--after", str(fixed), "--touched", "dead.py") == 0
    assert "verification: RESOLVED" in capsys.readouterr().out


def test_remediate_rejects_malformed_analysis_and_bad_output(monkeypatch, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]")
    assert _run(monkeypatch, tmp_path, "remediate", "--analysis", str(bad),
                "--finding", "x", "--option", "delete") == 2
    assert "expected a JSON object" in capsys.readouterr().err
    broken = tmp_path / "broken.json"
    broken.write_text("{oops")
    assert _run(monkeypatch, tmp_path, "verify-fix", "--before", str(broken),
                "--after", str(broken)) == 2
    capsys.readouterr()
    repo = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(monkeypatch, tmp_path, "analyze", str(repo),
                "--out", "/definitely/missing/dir/out.json") == 1
    assert "cannot write output" in capsys.readouterr().err
