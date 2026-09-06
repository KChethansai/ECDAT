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
    from app.scanner import ContainerScanner, HSMScanner

    assert ContainerScanner.is_mock is False  # REAL since Phase 9
    assert HSMScanner.is_mock is False  # REAL since Phase 10


def test_binary_scanner_is_real_and_skips_text():
    from app.scanner import BinaryScanner

    assert BinaryScanner().scan(SAMPLE) == []  # text fixtures: nothing binary
    assert BinaryScanner.is_mock is False


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
    health = c.get("/health").json()
    assert health["ok"] is True
    assert {"source", "hsm", "cloud", "runtime"} <= set(health["scanners"])
    assert health["runtimeProbe"] == "present"
    r = c.post("/scans", json={"target": "sample", "scanners": ["source"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["report"]["summary"]["real"] >= 5
    assert body["report"]["summary"]["mock"] == 0
    assert c.get(f"/reports/{body['id']}").status_code == 200
    m = c.post("/scans", json={"target": "sample", "scanners": ["source", "hsm"]})
    assert m.json()["report"]["mockWarning"] is None  # no mock scanners remain


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
                                  "scanners": ["container"]}).status_code == 404


# --- Phase 8: binary artifact discovery ------------------------------------

def _elf(*strings: bytes) -> bytes:
    return b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x00" * 48 + b"\x00".join(strings)


def _pe(*strings: bytes) -> bytes:
    return b"MZ" + b"\x00" * 58 + b"\x00".join(strings) + b"PE\x00\x00" + b"\x00".join(strings)


def _macho(*strings: bytes) -> bytes:
    return b"\xcf\xfa\xed\xfe" + b"\x00" * 12 + b"\x00".join(strings)


def test_binary_format_detection_and_evidence_tiers(tmp_path):
    from app.scanner import BinaryScanner

    target = tmp_path / "lib.bin"
    target.write_bytes(_elf(b"libcrypto.so.3", b"EVP_aes_256_gcm", b"RSA-2048", b"TLSv1.3"))
    findings = BinaryScanner().scan(target)
    assert findings and all(f.scanner == "binary" and f.is_mock is False for f in findings)
    by_usage = {f.usage for f in findings}
    assert {"binary library reference", "binary symbol reference",
            "binary string reference"} <= by_usage
    lib = next(f for f in findings if f.library == "libcrypto.so.3")
    assert lib.algorithm == "OpenSSL" and lib.confidence == 0.8
    rsa = next(f for f in findings if f.algorithm == "RSA" and f.usage == "binary string reference")
    assert rsa.key_size == 2048 and "does not prove runtime" in rsa.rationale
    assert all(len(f.evidence) <= 160 and "\n" not in f.evidence for f in findings)


def test_binary_pe_and_macho_formats(tmp_path):
    from app.scanner import BinaryScanner

    pe = tmp_path / "a.dll"
    pe.write_bytes(_pe(b"bcrypt.dll", b"BCryptEncrypt", b"AES-256-GCM"))
    macho = tmp_path / "b.dylib"
    macho.write_bytes(_macho(b"libssl.dylib", b"TLSv1.2"))
    assert any(f.library == "bcrypt.dll" for f in BinaryScanner().scan(pe))
    assert any(f.algorithm == "TLS" for f in BinaryScanner().scan(macho))


def test_binary_unsupported_truncated_oversized_and_missing(tmp_path):
    from app.scanner import BinaryScanner
    from app.scanner.binary_scanner import MAX_STRINGS
    from app.scanner.source_scanner import MAX_FILE_BYTES

    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\necho RSA-2048\n")
    assert BinaryScanner().scan(script) == []  # magic-gated: text is source's job
    truncated = tmp_path / "cut.bin"
    truncated.write_bytes(b"\x7fE")
    assert BinaryScanner().scan(truncated) == []
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * MAX_FILE_BYTES)
    assert BinaryScanner().scan(big) == []
    assert MAX_STRINGS > 0  # extraction bound exists (see extract_strings)
    try:
        BinaryScanner().scan(tmp_path / "missing.bin")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")


def test_binary_results_are_deterministic_and_deduped(tmp_path):
    from app.scanner import BinaryScanner

    target = tmp_path / "dup.bin"
    target.write_bytes(_elf(b"libcrypto.so.3", b"libcrypto.so.3", b"EVP_aes_256_gcm"))
    first = [f.to_dict() for f in BinaryScanner().scan(target)]
    second = [f.to_dict() for f in BinaryScanner().scan(target)]
    assert first == second  # repeated scans reproduce, including ids
    libs = [f for f in first if f["library"] == "libcrypto.so.3"]
    assert len(libs) == 1  # repeated strings collapse; distinct evidence stays


def test_binary_embedded_certificate_and_key_safety(tmp_path):
    from app.scanner import BinaryScanner

    pem = (SAMPLE.parent / "phase6" / "certificate.pem").read_text()
    blob = tmp_path / "with-cert.bin"
    blob.write_bytes(b"\x7fELF" + b"\x00" * 60 + pem.encode() + b"\x00PRIVATE BODY")
    findings = BinaryScanner().scan(blob)
    cert = next(f for f in findings if f.usage == "certificate metadata")
    assert cert.algorithm == "RSA" and cert.key_size == 2048 and cert.expires_at
    assert "PRIVATE BODY" not in " ".join(f.evidence for f in findings)

    key_blob = tmp_path / "with-key.bin"
    key_blob.write_bytes(b"\x7fELF" + b"\x00" * 60 +
                         b"-----BEGIN PRIVATE KEY-----\nSECRET-BYTES\n-----END PRIVATE KEY-----")
    for finding in BinaryScanner().scan(key_blob):
        assert "SECRET-BYTES" not in finding.evidence


def test_binary_flows_through_shared_pipeline_and_cbom(tmp_path):
    import json

    from app.pipeline import run_scan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('hashlib.md5(b"x")\n')
    (repo / "lib.bin").write_bytes(_elf(b"libcrypto.so.3", b"RSA-2048"))
    report = run_scan(repo, ["source", "binary"])
    scanners = {c["scanner"] for c in report["components"]}
    assert {"source", "binary"} <= scanners
    assert report["summary"]["mock"] == 0 and report["mockWarning"] is None
    for component in report["components"]:
        assert component["priority"] in ("P0", "P1", "P2", "P3")
        assert component["rationale"] and component["recommendation"]["recommend"]
    assert "binary" in report["metadata"]["scannerSources"]
    json.dumps(report)


# --- Phase 10: HSM + cloud configuration discovery --------------------------


# --- Phase 9: container + dependency discovery ------------------------------

def _layer(member_files: list[tuple[str, bytes]]) -> bytes:
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in member_files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _image_tar(layers: list[bytes], env: list[str] | None = None) -> bytes:
    import io
    import json as _json
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        entries = [{"Config": "config.json", "RepoTags": ["t:latest"],
                    "Layers": [f"layer{i}.tar" for i in range(len(layers))]}]
        config = {"config": {"Env": env or []}}
        for name, data in ([("manifest.json", _json.dumps(entries).encode()),
                            ("config.json", _json.dumps(config).encode())]
                           + [(f"layer{i}.tar", layer) for i, layer in enumerate(layers)]):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_container_image_tar_finds_config_layers_and_certs(tmp_path):
    from app.scanner import ContainerScanner

    cert = (SAMPLE.parent / "phase6" / "certificate.pem").read_bytes()
    image = tmp_path / "image.tar"
    image.write_bytes(_image_tar(
        [_layer([("etc/ssl/openssl.cnf", b"CipherString = DEFAULT\nTLSv1.2\n"),
                 ("app/requirements.txt", b"cryptography==42.0\n"),
                 ("etc/ssl/certs/ca.crt", cert)])],
        env=["APP_ENV=demo", "DB_PASSWORD=s3cret"]))
    findings = ContainerScanner().scan(image)
    assert findings and all(f.scanner == "container" and not f.is_mock for f in findings)
    usages = {f.usage for f in findings}
    assert {"container config reference", "container file reference",
            "certificate metadata"} <= usages
    secret = next(f for f in findings if f.algorithm == "ENV-SECRET")
    assert "DB_PASSWORD" in secret.evidence and "s3cret" not in secret.evidence
    assert all(len(f.evidence) <= 160 for f in findings)
    assert ContainerScanner.is_mock is False


def test_container_embedded_binary_and_dockerfile(tmp_path):
    from app.scanner import ContainerScanner

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.14\nRUN apt-get install -y openssl libssl3\n"
        "COPY tls/server.key /etc/ssl/private/\n")
    image = tmp_path / "with-bin.tar"
    image.write_bytes(_image_tar(
        [_layer([("usr/lib/libx.so", b"\x7fELF" + b"\x00" * 60 + b"libcrypto.so.3")])]))
    dockerfile_hits = ContainerScanner().scan(repo)
    assert any(f.algorithm == "OpenSSL" for f in dockerfile_hits)
    assert any(f.algorithm == "KEYFILE" for f in dockerfile_hits)
    binary_hits = ContainerScanner().scan(image)
    assert any(f.usage == "container binary reference" and f.library == "libcrypto.so.3"
               for f in binary_hits)


def test_container_attacks_fail_safely(tmp_path):
    import io
    import tarfile

    from app.scanner import ContainerScanner

    evil = tmp_path / "evil.tar"
    with tarfile.open(evil, mode="w") as tar:
        for name in ("../../pwned", "/abs", "link"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE if name == "link" else tarfile.REGTYPE
            info.linkname = "/etc/passwd" if name == "link" else ""
            data = b"RSA-2048\n"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        payload = tmp_path / "sentinel"
        assert not payload.exists()
        ContainerScanner().scan(evil)
        assert not payload.exists()  # nothing extracted, nothing executed

    garbage = tmp_path / "garbage.tar"
    garbage.write_bytes(b"\x00" * 2048)
    assert ContainerScanner().scan(garbage) == []
    (tmp_path / "plain.txt").write_text("hello\n")
    assert ContainerScanner().scan(tmp_path / "plain.txt") == []


def test_container_results_deterministic(tmp_path):
    from app.scanner import ContainerScanner

    image = tmp_path / "image.tar"
    image.write_bytes(_image_tar(
        [_layer([("etc/ssl/openssl.cnf", b"TLSv1.2\n")])], env=["A=1"]))
    first = [f.to_dict() for f in ContainerScanner().scan(image)]
    second = [f.to_dict() for f in ContainerScanner().scan(image)]
    assert first == second and first


def test_dependency_manifests_across_ecosystems(tmp_path):
    from app.scanner import DependencyScanner

    (tmp_path / "requirements.txt").write_text("cryptography>=42,<43\nrequests==2.31\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"jsonwebtoken": "^9.0"}}')
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["pycryptodome==3.20"]\n')
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nring = "0.17"\n')
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.21\nrequire golang.org/x/crypto v0.17.0\n")
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>bcprov-jdk18</artifactId>"
        "<version>1.77</version></dependency></dependencies></project>")
    (tmp_path / "build.gradle").write_text('implementation "org.bouncycastle:bcprov-jdk18:1.77"\n')
    findings = DependencyScanner().scan(tmp_path)
    assert findings and all(f.scanner == "dependency" and not f.is_mock for f in findings)
    versions = {(f.library, f.evidence) for f in findings}
    assert any("cryptography" in lib and "42" in ev for lib, ev in versions)
    assert any("jsonwebtoken" in lib and "9.0" in ev for lib, ev in versions)
    assert any("bcprov-jdk18" in lib and "1.77" in ev for lib, ev in versions)
    assert all(f.usage == "dependency reference" and f.category == "dependency"
               for f in findings)
    assert DependencyScanner.is_mock is False


def test_dependency_false_positives_and_malformed_input(tmp_path):
    from app.scanner import DependencyScanner

    (tmp_path / "requirements.txt").write_text(
        "authlib==1.0\nsecure-utils==2.0\ncryptography-vectors==42.0\n")
    assert DependencyScanner().scan(tmp_path) == []  # substrings are not evidence
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "package.json").write_text("{not json")
    (bad / "pom.xml").write_text("<project><oops>")
    (bad / "notes.txt").write_text("cryptography\n")
    assert DependencyScanner().scan(bad) == []


def test_dependency_requirements_includes_followed_safely(tmp_path):
    from app.scanner import DependencyScanner

    (tmp_path / "requirements.txt").write_text("-r extra.txt\nflask==3.0\n")
    (tmp_path / "extra.txt").write_text("bcrypt==4.1\n-r requirements.txt\n")  # cycle
    findings = DependencyScanner().scan(tmp_path / "requirements.txt")
    assert any(f.library == "bcrypt" for f in findings)


def test_full_pipeline_covers_all_real_scanners(tmp_path):
    import json

    from app.pipeline import run_scan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('hashlib.md5(b"x")\n')
    (repo / "lib.bin").write_bytes(_elf(b"libcrypto.so.3"))
    (repo / "Dockerfile").write_text("FROM x\nRUN apt-get install -y openssl\n")
    (repo / "requirements.txt").write_text("cryptography==42.0\n")
    report = run_scan(repo, None)  # defaults: all REAL scanners
    assert {c["scanner"] for c in report["components"]} == {"source", "binary", "container",
                                                            "dependency"}
    assert report["summary"]["mock"] == 0 and report["mockWarning"] is None
    for component in report["components"]:
        assert component["priority"] in ("P0", "P1", "P2", "P3")
        assert component["rationale"] and component["recommendation"]["recommend"]
    json.dumps(report)


def test_api_default_scanners_cover_all_real_scanners():
    from fastapi.testclient import TestClient

    from app.main import app

    body = TestClient(app).post("/scans", json={"target": "sample"}).json()["report"]
    assert body["metadata"]["scannerSources"] == ["binary", "cloud", "container",
                                                      "dependency", "hsm", "source"]


# --- Phase 10: HSM + cloud configuration discovery --------------------------

def test_hsm_pkcs11_uri_module_and_vendor_evidence(tmp_path):
    from app.scanner import HSMScanner

    conf = tmp_path / "hsm.conf"
    conf.write_text(
        "pkcs11:token=ProdHSM;object=sign-key;type=private;pin-value=s3cret\n"
        "PKCS11_MODULE=/usr/lib/opensc-pkcs11.so\n"
        "SunPKCS11 slot\n"
        "HSM_SLOT=3\n"
        "thales Luna partition\n"
        "just talking about lunch\n")
    findings = HSMScanner().scan(conf)
    assert findings and all(f.scanner == "hsm" and not f.is_mock for f in findings)
    uri = next(f for f in findings if f.library == "PKCS#11 URI")
    assert "ProdHSM" in uri.evidence and "s3cret" not in uri.evidence
    assert "pin-value" not in uri.evidence
    assert any(f.library == "/usr/lib/opensc-pkcs11.so" for f in findings)
    assert not [f for f in findings if "lunch" in f.evidence]
    assert HSMScanner.is_mock is False


def test_hsm_missing_target_and_empty_dir(tmp_path):
    from app.scanner import HSMScanner

    empty = tmp_path / "empty"
    empty.mkdir()
    assert HSMScanner().scan(empty) == []
    try:
        HSMScanner().scan(empty / "nope.conf")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")


def test_cloud_aws_azure_gcp_evidence_and_redaction(tmp_path):
    from app.scanner import CloudScanner

    infra = tmp_path / "main.tf"
    infra.write_text(
        'resource "aws_kms_key" "a" {}\n'
        'key_id = "arn:aws:kms:us-east-1:123456789012:key/abcd"\n'
        'vault = "https://v.vault.azure.net/keys/k/1"\n'
        'gcp = "projects/p/locations/u/keyRings/r/cryptoKeys/k"\n'
        'DB_PASSWORD = "hunter2"\n'
        'policy = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"\n')
    findings = CloudScanner().scan(infra)
    assert findings and all(f.scanner == "cloud" and not f.is_mock for f in findings)
    arn = next(f for f in findings if "arn:aws:kms" in f.evidence)
    assert "****" in arn.evidence and "123456789012" not in arn.evidence
    assert "hunter2" not in " ".join(f.evidence for f in findings)
    assert {f.algorithm for f in findings} >= {"KMS", "KEYVAULT", "TLS"}
    assert CloudScanner.is_mock is False


def test_cloud_false_positives_and_malformed_input(tmp_path):
    from app.scanner import CloudScanner

    notes = tmp_path / "notes.md"
    notes.write_text("ask aws support about the keyboard vault mural\n")
    assert CloudScanner().scan(notes) == []
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    assert CloudScanner().scan(bad) == []


def test_hsm_cloud_recommendations_are_inventory_guidance():
    from app.recommend import recommend

    for algo in ("PKCS11", "HSM", "KMS", "KEYVAULT", "CLOUDHSM", "ENV-SECRET", "TLS"):
        rec = recommend(algo)
        assert rec["recommend"] and rec["notes"] and rec["guidance"]
    assert "ML-KEM" not in recommend("KMS")["recommend"]  # KMS is not a drop-in for PQC
    assert "quantum-safe" not in recommend("HSM")["recommend"].lower()


# --- Phase 11: controlled runtime discovery ----------------------------------

def test_runtime_opt_in_and_static_default():
    from app.pipeline import run_scan

    static_only = run_scan(SAMPLE, ["source"])
    assert [c for c in static_only["components"] if c["scanner"] == "runtime"] == []
    assert static_only["metadata"]["runtimeProvenance"] == {"available": False}


def test_runtime_probe_observes_fixture_and_correlates(tmp_path):
    from app.pipeline import run_scan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    report = run_scan(repo, None, runtime=True)
    runtime_rows = [c for c in report["components"] if c["scanner"] == "runtime"]
    assert len(runtime_rows) == 6  # the six fixture operations, no more no less
    assert all(r["usage"] == "runtime observation" and not r["is_mock"] for r in runtime_rows)
    assert all(r["priority"] in ("P0", "P1", "P2", "P3") and r["rationale"]
               and r["recommendation"]["recommend"] for r in runtime_rows)
    sha = next(r for r in runtime_rows if r["algorithm"] == "SHA-256")
    assert sha["correlation"]["supports"]  # static hashlib/SHA-256 evidence linked
    assert all(s != sha["id"] for s in sha["correlation"]["supports"])
    assert report["metadata"]["runtimeProvenance"]["available"] is True
    assert "runtime" in report["metadata"]["scannerSources"]
    import json as _json
    _json.dumps(report)


def test_runtime_unavailable_degrades_gracefully(tmp_path):
    from app.scanner.runtime_scanner import RuntimeScanner, RuntimeUnavailableError

    missing = RuntimeScanner(probe=tmp_path / "nope.py")
    try:
        missing.scan(tmp_path)
    except RuntimeUnavailableError:
        pass
    else:
        raise AssertionError("expected RuntimeUnavailableError")
    slow = tmp_path / "slow.py"
    slow.write_text("import time\ntime.sleep(60)\n")
    try:
        RuntimeScanner(probe=slow, timeout=1).scan(tmp_path)
    except RuntimeUnavailableError as exc:
        assert "terminated" in str(exc)
    else:
        raise AssertionError("expected timeout termination")
    # no lingering probe processes
    import subprocess as _sp
    leftovers = _sp.run(["pgrep", "-f", "slow.py"], capture_output=True, text=True)
    assert leftovers.returncode != 0


def test_runtime_redacts_secrets_and_ignores_noise(tmp_path):
    from app.scanner.runtime_scanner import RuntimeScanner

    noisy = tmp_path / "noisy.py"
    noisy.write_text(
        'print("ECDAT-TELEMETRY v=1 lib=hashlib algo=SHA-256 op=digest")\n'
        'print("password=hunter2 token=abc secret=xyz")\n'
        'print("garbage line")\n'
        'print("ECDAT-TELEMETRY v=1 lib=x")\n')
    findings = RuntimeScanner(probe=noisy).scan(tmp_path)
    assert len(findings) == 1 and findings[0].algorithm == "SHA-256"
    assert "hunter2" not in findings[0].evidence


def test_runtime_api_requires_explicit_opt_in():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    default = client.post("/scans", json={"target": "sample"}).json()["report"]
    assert [c for c in default["components"] if c["scanner"] == "runtime"] == []
    opted = client.post("/scans", json={"target": "sample", "runtime": True}).json()["report"]
    assert any(c["scanner"] == "runtime" for c in opted["components"])
    assert opted["metadata"]["runtimeProvenance"]["available"] is True


def test_correlation_matches_families_not_spellings():
    from app.pipeline import _canon, correlate

    assert _canon("SHA-256") == _canon("SHA-512") == _canon("SHA-2")
    assert _canon("HMAC-SHA256") == _canon("HMAC")
    assert _canon("PBKDF2") == _canon("KDF")
    assert _canon("TLSv1.3") == _canon("TLS") == _canon("TLS1.2")
    static = {"id": "s1", "scanner": "source", "algorithm": "SHA-2", "is_mock": False}
    observed = {"id": "r1", "scanner": "runtime", "algorithm": "SHA-512",
                "is_mock": False}
    rows = [static, observed]
    correlate(rows)
    assert rows[1]["correlation"]["supports"] == ["s1"]
    assert "id" not in rows[0] or "correlation" not in rows[0]


# --- Phase 12: unified intelligence ------------------------------------------

def _rows():
    return [
        {"id": "a1", "scanner": "source", "algorithm": "RSA", "category": "asymmetric",
         "file_path": "tls.conf", "line": 3, "key_size": 2048, "curve": "", "mode": "",
         "protocol_version": "", "library": "", "usage": "direct", "confidence": 0.85,
         "severity": "high", "priority": "P1", "is_mock": False},
        {"id": "a2", "scanner": "dependency", "algorithm": "OpenSSL", "category": "library",
         "file_path": "requirements.txt", "line": 0, "key_size": None, "curve": "",
         "mode": "", "protocol_version": "", "library": "openssl", "usage": "dependency reference",
         "confidence": 0.8, "severity": "low", "priority": "P3", "is_mock": False},
        {"id": "a3", "scanner": "binary", "algorithm": "RSA-2048", "category": "asymmetric",
         "file_path": "lib.bin", "line": 0, "key_size": 2048, "curve": "", "mode": "",
         "protocol_version": "", "library": "", "usage": "binary string reference",
         "confidence": 0.55, "severity": "high", "priority": "P1", "is_mock": False},
    ]


def test_strength_is_qualitative_not_probabilistic():
    from app.intelligence import strength

    assert strength({"usage": "runtime observation", "confidence": 0.85}) == "HIGH"
    assert strength({"usage": "certificate metadata", "confidence": 0.95}) == "HIGH"
    assert strength({"usage": "binary string reference", "confidence": 0.55}) == "LOW"
    assert strength({"usage": "direct", "confidence": 0.9}) == "HIGH"
    assert strength({"usage": "dependency reference", "confidence": 0.8}) == "MEDIUM"
    assert strength({"usage": "direct", "confidence": "junk"}) == "LOW"


def test_relate_preserves_evidence_and_marks_non_observation_honestly():
    from app.intelligence import relate

    rows = _rows()
    relate(rows)
    by_id = {r["id"]: r for r in rows}
    # same family across scanners, evidence kept separate (never self-linked)
    assert {"a3"} == {link["id"] for link in by_id["a1"]["related"]
                      if link["relation"] == "same-family"}
    # no runtime rows: nobody claims runtime observation, nobody claims absence
    assert all("runtime-observed" not in {link["relation"] for link in r["related"]}
               for r in rows)
    assert all(len(r["related"]) <= 8 for r in rows)
    again = _rows()
    relate(again)
    assert [r["related"] for r in rows] == [r["related"] for r in again]


def test_inventory_and_graph_are_deterministic_and_json_safe():
    import json as _json

    from app.intelligence import build_graph, build_inventory

    inventory = build_inventory(_rows())
    assert [row["family"] for row in inventory] == ["OPENSSL", "RSA"]
    rsa = next(row for row in inventory if row["family"] == "RSA")
    assert rsa["scanners"] == ["binary", "source"] and rsa["findingCount"] == 2
    assert rsa["priority"] == "P1" and rsa["runtimeObserved"] is False
    assert rsa["recommendation"] and rsa["findingIds"] == ["a1", "a3"]
    graph = build_graph(_rows())
    kinds = {node["type"] for node in graph["nodes"]}
    assert {"artifact", "algorithm", "finding", "library"} <= kinds
    assert _json.dumps({"inventory": inventory, "graph": graph})


# --- Phase 13: migration intelligence ------------------------------------------

def test_migration_status_never_claims_completion():
    from app.migration import build_plan, status_for

    assert status_for({"id": "x", "severity": "critical", "priority": "P0"}, {}) == \
        "MIGRATION_REQUIRED"
    assert status_for({"id": "x", "severity": "low", "priority": "P3"}, {}) == "DISCOVERED"
    assert status_for({"id": "x", "severity": "low", "priority": "P3"},
                      {"x": "MIGRATION_IN_PROGRESS"}) == "MIGRATION_IN_PROGRESS"
    try:
        status_for({"id": "x", "severity": "low", "priority": "P3"}, {"x": "DONE"})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown status")
    plan = build_plan([], [], {"data_years": 10, "migration_years": 3, "qrqc_years_left": 10})
    assert plan["workItems"] == [] and plan["statusCounts"] == {}


def test_migration_plan_roadmap_and_work_items():
    import json as _json

    from app.migration import build_plan

    rows = _rows()
    for row in rows:
        row.update({"rationale": "test reason",
                    "recommendation": {"recommend": "do X", "notes": "n"}})
    plan = build_plan(rows, [], {"data_years": 10, "migration_years": 3, "qrqc_years_left": 10})
    assert plan["roadmap"]["Near-term"] and plan["roadmap"]["Monitor"]
    rsa_item = next(item for item in plan["workItems"] if item["family"] == "RSA")
    assert rsa_item["priority"] == "P1" and rsa_item["status"] == "MIGRATION_REQUIRED"
    assert rsa_item["direction"] == recommend("RSA")["recommend"]  # real guidance, not test text
    assert rsa_item["artifactCount"] == 2
    assert any("unknown" in unknown for unknown in rsa_item["unknowns"])
    assert "not a quantum-arrival prediction" in _json.dumps(plan)
    assert _json.dumps(plan)


def test_report_carries_intelligence_migration_and_contract():
    import json as _json

    from app.pipeline import run_scan

    report = run_scan(SAMPLE, ["source"])
    assert report["intelligence"]["inventory"] and report["intelligence"]["graph"]["nodes"]
    assert report["migration"]["workItems"] and report["migration"]["roadmap"]["Immediate"]
    assert all("migrationStatus" in c and "evidenceStrength" in c and "related" in c
               for c in report["components"])
    _json.dumps(report)
