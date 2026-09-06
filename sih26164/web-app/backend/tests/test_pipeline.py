"""Backend tests: real scanner discovery, mock labeling, risk/CBOM, API flow."""

import json
from pathlib import Path

from app.cbom import build_cbom
from app.models import CryptoFinding, normalize_findings
from app.recommend import recommend
from app.risk import assess, mosca_exposed
from app.scanner import BinaryScanner, SourceScanner

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "vuln_sample"


def test_source_scanner_finds_real_artefacts():
    findings = SourceScanner().scan(SAMPLE)
    assert findings and all(f.is_mock is False for f in findings)
    algos = {f.algorithm for f in findings}
    assert {"MD5", "SHA-1", "DES", "TLS1.0"} <= algos
    assert any(f.algorithm == "RSA" and f.key_size == 1024 for f in findings)


def test_certificate_metadata_is_real_and_private_material_is_redacted(tmp_path):
    fixture = SAMPLE.parent / "phase6" / "certificate.pem"
    findings = SourceScanner().scan(fixture)
    certificate = next(f for f in findings if f.usage == "certificate metadata")
    assert certificate.algorithm == "RSA" and certificate.key_size == 2048
    assert certificate.signature_algorithm == "SHA-256-RSA" and certificate.expires_at

    private = tmp_path / "private.pem"
    private.write_text("-----BEGIN PRIVATE KEY-----\nnot-a-secret\n-----END PRIVATE KEY-----\n")
    private_findings = SourceScanner().scan(private)
    assert private_findings and all("not-a-secret" not in f.evidence for f in private_findings)
    assert any("REDACTED PRIVATE KEY" in f.evidence for f in private_findings)


def test_dependency_reference_is_not_direct_algorithm_usage(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("cryptography==42.0\n")
    findings = SourceScanner().scan(manifest)
    dependency = next(f for f in findings if f.category == "dependency")
    assert dependency.usage == "dependency reference"
    assert "does not prove" in dependency.rationale


def test_public_key_reference_is_discovered_without_reading_key_contents(tmp_path):
    config = tmp_path / "service.conf"
    config.write_text("public_key_path=certs/service.key\n")
    finding = next(f for f in SourceScanner().scan(config) if f.algorithm == "KEYFILE")
    assert finding.category == "key" and "service.key" in finding.evidence


def test_keyfile_ignores_code_attribute_access_but_keeps_filename_refs(tmp_path):
    code = tmp_path / "app.py"
    code.write_text("result = args.key\nvalue = mem.kv_get(name)\n")
    assert [f for f in SourceScanner().scan(code) if f.algorithm == "KEYFILE"] == []
    conf = tmp_path / "real.conf"
    conf.write_text('keyfile = certs/service.key\ncert = "server.pem"\nquoted = \'backup.key\'\n')
    keyfiles = [f for f in SourceScanner().scan(conf) if f.algorithm == "KEYFILE"]
    assert len(keyfiles) == 3


def test_generated_directories_are_skipped(tmp_path):
    vendored = tmp_path / "vendor" / "lib"
    vendored.mkdir(parents=True)
    (vendored / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assert SourceScanner().scan(tmp_path) == []


def test_unreadable_file_metadata_never_crashes_scan(tmp_path):
    from app.scanner.source_scanner import _size_ok

    assert _size_ok(tmp_path / "missing.py") is False
    assert SourceScanner().scan(tmp_path) == []


def test_cors_allows_only_local_dashboard_origins():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    allowed = client.options("/scans", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    denied = client.options("/scans", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in denied.headers


def test_normalization_removes_only_identical_hits():
    first = CryptoFinding(scanner="source", file_path="x.py", line=1, algorithm="RSA",
                          category="asymmetric")
    duplicate = CryptoFinding(scanner="source", file_path="x.py", line=1, algorithm="RSA",
                              category="asymmetric")
    separate = CryptoFinding(scanner="source", file_path="x.py", line=2, algorithm="RSA",
                             category="asymmetric")
    assert normalize_findings([first, duplicate, separate]) == [first, separate]


def test_mock_scanners_flagged():
    findings = BinaryScanner().scan(SAMPLE)
    assert findings and all(f.is_mock for f in findings)


def test_mosca_and_severity():
    assert mosca_exposed(10, 3, 10) is True
    assert mosca_exposed(2, 1, 10) is False
    f = CryptoFinding(scanner="source", file_path="x", line=1, algorithm="RSA",
                      category="asymmetric", key_size=1024)
    (row,) = assess([f], 10, 3, 10)
    assert row["severity"] == "critical" and row["mosca_exposed"] is True
    assert row["priority"] == "P0" and "RSA key below" in row["rationale"]


def test_recommendation_and_cbom_labeling():
    assert "ML-KEM" in recommend("RSA")["recommend"]
    real = CryptoFinding(scanner="source", file_path="x", line=1, algorithm="MD5", category="hash")
    mock = CryptoFinding(scanner="binary(MOCK)", file_path="y", line=0, algorithm="RSA",
                         category="asymmetric", is_mock=True)
    enriched = assess([real, mock])
    for finding in enriched:
        finding["recommendation"] = recommend(finding["algorithm"])
    cbom = build_cbom("t", enriched, {"available": True, "chars": 40})
    assert cbom["summary"]["total"] == 2
    assert cbom["summary"]["mock"] == 1 and cbom["mockWarning"] is not None
    assert cbom["metadata"]["contextProvenance"]["chars"] == 40
    assert cbom["riskSummary"]["priorities"] and cbom["recommendations"]
    assert "Migration guidance" in recommend("RSA")["guidance"]


def test_malformed_empty_and_large_inputs_are_safe(tmp_path):
    malformed = tmp_path / "bad.pem"
    malformed.write_text("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n")
    assert not [f for f in SourceScanner().scan(malformed) if f.usage == "certificate metadata"]
    empty = tmp_path / "empty.py"
    empty.write_text("")
    assert SourceScanner().scan(empty) == []


def test_empty_scan_produces_valid_cbom_report(tmp_path):
    from app.pipeline import run_scan

    empty = tmp_path / "empty-project"
    empty.mkdir()
    report = run_scan(empty, ["source"])
    assert report["summary"]["total"] == 0
    assert report["metadata"]["scannerSources"] == ["source"]
    assert report["riskSummary"]["moscaExposed"] == 0
    json.dumps(report)


def test_api_scan_flow():
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    assert c.get("/health").json()["ok"] is True
    r = c.post("/scans", json={"target": "sample", "scanners": ["source"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["report"]["summary"]["real"] >= 5
    assert body["report"]["summary"]["mock"] == 0
    assert c.get(f"/reports/{body['id']}").status_code == 200
    m = c.post("/scans", json={"target": "sample", "scanners": ["source", "binary"]})
    assert m.json()["report"]["mockWarning"] is not None


def test_api_and_shared_pipeline_produce_compatible_reports():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.pipeline import run_scan

    api_report = TestClient(app).post(
        "/scans", json={"target": "sample", "scanners": ["source"]}
    ).json()["report"]
    pipeline_report = run_scan(SAMPLE, ["source"])
    for report in (api_report, pipeline_report):
        report.pop("scannedAt")
    assert api_report == pipeline_report


def test_api_error_paths():
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    assert c.post("/scans", json={"target": "sample", "scanners": ["nope"]}).status_code == 400
    assert c.post("/scans", json={"target": "/definitely/missing/xyz"}).status_code == 404
    assert c.post("/scans", json={"target": "sample", "data_years": -1}).status_code == 422
    assert c.get("/reports/doesnotexist").status_code == 404


def test_api_rejects_existing_targets_outside_workspace(tmp_path):
    from fastapi.testclient import TestClient

    from app.main import app

    outside = tmp_path / "outside.py"
    outside.write_text("RSA 2048\n")
    response = TestClient(app).post("/scans", json={"target": str(outside)})
    assert response.status_code == 400
    assert response.json()["detail"] == "unsafe scan target"


def test_duplicate_scanners_deduped():
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    once = c.post("/scans", json={"target": "sample", "scanners": ["source"]}).json()["report"]
    twice = c.post("/scans", json={"target": "sample",
                                   "scanners": ["source", "source"]}).json()["report"]
    assert twice["summary"]["total"] == once["summary"]["total"]


def test_reports_capped():
    from fastapi.testclient import TestClient

    import app.main as main_mod

    c = TestClient(main_mod.app)
    for _ in range(main_mod.MAX_REPORTS + 5):
        c.post("/scans", json={"target": "sample", "scanners": ["source"]})
    assert len(main_mod.REPORTS) <= main_mod.MAX_REPORTS


def test_scanner_skips_symlinks_and_oversized_files(tmp_path):
    from app.scanner import SourceScanner
    from app.scanner.source_scanner import MAX_FILE_BYTES

    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "secret.txt"
    victim.write_text("RSA private key 2048 bits here\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "evil-link.py").symlink_to(victim)  # points outside the scan root
    big = repo / "big.py"
    with open(big, "w") as fh:
        fh.write("x = 'MD5'\n")
        fh.seek(MAX_FILE_BYTES + 10)
        fh.write("RSA 4096\n")
    assert SourceScanner().scan(repo) == []  # symlink + oversized file both skipped
    assert SourceScanner().scan(big) == []  # size cap applies to single-file targets too


def test_source_scanner_redacts_sensitive_evidence(tmp_path):
    source = tmp_path / "crypto.py"
    source.write_text('RSA private_key = "not-a-real-secret"\n')
    findings = SourceScanner().scan(source)
    assert findings
    assert all("not-a-real-secret" not in finding.evidence for finding in findings)
    assert any("[REDACTED]" in finding.evidence for finding in findings)


def test_mock_missing_target_is_404():
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    assert c.post("/scans", json={"target": "/definitely/missing/xyz",
                                  "scanners": ["binary"]}).status_code == 404
