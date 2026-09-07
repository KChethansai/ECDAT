"""Active validation: safety, strategies, bounded probes, correlation, SARIF, API."""

import json
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.pipeline import run_scan
from app.validation import (ValidationPolicy, apply_correlation, check_url, run_validations,
                            strategy_for, to_sarif)
from app.validation.correlate import correlate_finding
from app.validation.http_probe import _redact as redact_headers
from app.validation.models import CORRELATION_STATUSES, VALIDATION_STATUSES, ValidationResult

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "vuln_sample"


# --- safety policy -----------------------------------------------------------

def test_loopback_allowed_non_loopback_blocked_by_default():
    policy = ValidationPolicy()
    assert check_url("https://127.0.0.1:8443/x", policy)[1] == "127.0.0.1"
    assert check_url("http://localhost:80/", policy)[1] == "localhost"
    with pytest.raises(ValueError):
        check_url("https://example.com/", policy)
    allowed = ValidationPolicy(allowlist_hosts=("example.com",))
    assert check_url("https://example.com/", allowed)[1] == "example.com"
    acked = ValidationPolicy(allow_non_loopback=True)
    assert check_url("https://example.com/", acked)[1] == "example.com"


def test_credentials_schemes_and_control_chars_rejected():
    policy = ValidationPolicy(allow_non_loopback=True)
    for bad in ("https://user:pass@127.0.0.1/", "ftp://127.0.0.1/x",
                "https://127.0.0.1:99999/", "https://127.0.0.1/x\ny",
                "https://127.0.0.1\\@evil/", ""):
        with pytest.raises(ValueError):
            check_url(bad, policy)


def test_policy_bounds_rejected():
    for override in ({"timeout_s": 0}, {"timeout_s": 61}, {"max_requests": 0},
                     {"max_requests": 201}, {"max_redirects": 11},
                     {"max_bytes": 100}, {"max_duration_s": 0}):
        with pytest.raises(ValueError):
            ValidationPolicy.from_dict(override)
    assert ValidationPolicy.from_dict({"dry_run": True}).dry_run is True
    with pytest.raises(ValueError):
        ValidationPolicy.from_dict({"allowlist_hosts": "not-a-list-of-hosts-ok"})
    # string is iterable; must still produce a sane policy, never crash
    assert isinstance(ValidationPolicy.from_dict({"allowlist_hosts": []}).allowlist_hosts, tuple)


# --- strategies ---------------------------------------------------------------

def _finding(algorithm="TLS1.2", category="protocol", usage="direct", is_mock=False):
    return {"id": "f1", "algorithm": algorithm, "category": category,
            "usage": usage, "is_mock": is_mock}


def test_strategies_map_deterministically():
    assert strategy_for(_finding())[0] == "tls"
    assert strategy_for(_finding("RSA", "certificate", "certificate metadata"))[0] == "tls"
    assert strategy_for(_finding("AES-256", "symmetric"))[0] == "runtime"
    assert strategy_for(_finding("MD5", "hash"))[0] == "runtime"
    assert strategy_for(_finding("x", "dependency", "dependency reference"))[0] == "runtime"
    assert strategy_for({**_finding(), "is_mock": True}) == (None, "mock findings are never actively validated")
    assert strategy_for(_finding("SHA-256", "hash", "dependency integrity metadata"))[0] is None
    assert strategy_for(_finding("ENV-SECRET", "key"))[0] is None
    assert strategy_for(_finding("RSA", "key", "public key reference"))[0] == "tls"
    assert strategy_for({})[0] is None
    assert strategy_for("nope")[0] is None


def test_model_rejects_unknown_statuses():
    with pytest.raises(ValueError):
        ValidationResult(status="EXPLOITED")
    with pytest.raises(ValueError):
        ValidationResult(correlation_status="PWNED")
    assert set(VALIDATION_STATUSES) >= {"CONFIRMED", "NOT_CONFIRMED", "BLOCKED", "ERROR"}
    assert set(CORRELATION_STATUSES) >= {"STATIC_ONLY", "RUNTIME_CONFIRMED"}


# --- dry run: no network -------------------------------------------------------

def test_dry_run_sends_no_requests():
    report = run_scan(SAMPLE, ["source"])
    run = run_validations(report["components"], ["https://127.0.0.1:9/"],
                          ValidationPolicy(dry_run=True))
    assert run["dry_run"] is True and run["summary"]["requests"] == 0
    assert run["summary"]["total"] > 0
    assert set(run["summary"]["byStatus"]) == {"BLOCKED"}
    assert all(r["error"] == "dry run — no request sent" for r in run["results"])


def test_blocked_targets_recorded_not_probed():
    report = run_scan(SAMPLE, ["source"])
    run = run_validations(report["components"], ["https://example.com/"],
                          ValidationPolicy())
    assert len(run["blocked_targets"]) == 1 and run["summary"]["requests"] == 0


# --- live loopback probes -------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _TLSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Strict-Transport-Security", "max-age=60")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def tls_server(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI required for the throwaway test certificate")
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=127.0.0.1"], check=True, capture_output=True, timeout=60)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    server = HTTPServer(("127.0.0.1", 0), _TLSHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()


def test_tls_probe_observes_real_handshake(tls_server):
    report = run_scan(SAMPLE, ["source"])
    url = f"https://127.0.0.1:{tls_server}/"
    first = run_validations(report["components"], [url], ValidationPolicy())
    second = run_validations(report["components"], [url], ValidationPolicy())
    assert first["summary"]["requests"] >= 1
    by_status = [(r["finding_id"], r["status"]) for r in first["results"]]
    assert by_status == [(r["finding_id"], r["status"]) for r in second["results"]]  # deterministic
    tls_rows = [r for r in first["results"] if r["validation_type"] == "tls" and r["finding_id"]]
    assert tls_rows
    sample = tls_rows[0]
    assert sample["observed_protocol"].startswith("TLSv1")
    assert sample["observed_cipher"] and sample["endpoint"] == url
    assert sample["evidence"]["http"]["hsts"] is True
    assert sample["status"] in ("CONFIRMED", "PARTIALLY_CONFIRMED", "NOT_CONFIRMED")
    # Static evidence untouched: same findings with validation on or off.
    plain = run_scan(SAMPLE, ["source"])
    assert [c["id"] for c in plain["components"]] == [c["id"] for c in report["components"]]
    for before, after in zip(plain["components"], report["components"]):
        for key in ("algorithm", "severity", "priority", "rationale", "evidence"):
            assert before[key] == after[key]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
        else:
            body = b"hello"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Strict-Transport-Security", "max-age=60")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()


def test_http_probe_follows_redirects_and_reads_hsts(http_server):
    from app.validation.http_probe import probe_http

    budget = {"requests": 0, "bytes": 0, "started": __import__("time").monotonic()}
    result = probe_http(f"http://127.0.0.1:{http_server}/redir", ValidationPolicy(), budget)
    assert result["status"] == 200 and result["hsts"] is True
    assert len(result["hops"]) == 2 and result["body_bytes"] == 5


def test_sensitive_headers_redacted():
    headers = redact_headers([("Authorization", "Bearer s3cret"), ("Content-Type", "text/html")])
    assert headers["Authorization"] == "[REDACTED]" and headers["Content-Type"] == "text/html"


# --- correlation ------------------------------------------------------------------

def test_correlation_rollup_is_additive():
    finding = {"id": "f1", "algorithm": "RSA", "is_mock": False, "usage": "direct"}
    confirmed = {"validation_id": "v1", "finding_id": "f1", "status": "CONFIRMED",
                 "validation_type": "tls"}
    status, ids = correlate_finding(finding, [confirmed])
    assert (status, ids) == ("RUNTIME_CONFIRMED", ["v1"])
    rows = [dict(finding), {"id": "f2", "algorithm": "AES", "is_mock": False, "usage": "direct"}]
    apply_correlation(rows, [confirmed])
    assert rows[0]["validationStatus"] == "RUNTIME_CONFIRMED"
    assert rows[1]["validationStatus"] == "STATIC_ONLY"
    assert set(rows[0]) >= {"validationStatus", "correlatedValidations"}


def test_sarif_output_shape():
    report = run_scan(SAMPLE, ["source"])
    doc = to_sarif(report, [])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ECDAT"
    assert len(run["results"]) == len(report["components"])
    assert all(r["level"] in ("error", "warning", "note") for r in run["results"])
    json.dumps(doc)


# --- API --------------------------------------------------------------------------

def test_api_scan_with_validation_and_revalidation_flow():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    body = client.post("/scans", json={"target": "sample", "scanners": ["source"],
                                       "validate": True}).json()["report"]
    assert body["validationSummary"]["total"] >= 0
    assert all("validationStatus" in c for c in body["components"])
    rid = client.post("/scans", json={"target": "sample",
                                      "scanners": ["source"]}).json()["id"]
    run = client.post("/validations", json={"report_id": rid, "targets": [],
                                            "policy": {"dry_run": True}}).json()["run"]
    assert run["dry_run"] is True and run["summary"]["requests"] == 0
    assert client.get(f"/validations/{run['run_id']}").status_code == 200
    assert client.get(f"/reports/{rid}/sarif").status_code == 200
    assert client.get("/reports/doesnotexist/sarif").status_code == 404
    assert client.post("/validations", json={"report_id": "nope"}).status_code == 404
    assert client.post("/validations", json={"report_id": rid,
                                             "policy": {"timeout_s": 999}}).status_code == 400
    assert client.get("/validations/nope").status_code == 404


def test_ipv6_loopback_and_port_coercion():
    from app.validation.safety import check_host_port

    assert check_host_port("::1", 443, ValidationPolicy()) == ("::1", 443)
    assert check_host_port("127.0.0.1", "443", ValidationPolicy()) == ("127.0.0.1", 443)
    with pytest.raises(ValueError):
        check_host_port("127.0.0.1", "notaport", ValidationPolicy())
    with pytest.raises(ValueError):
        check_host_port("example.com", 443, ValidationPolicy())


def test_api_rejects_oversized_payloads_and_long_targets():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    assert client.post("/scans", json={"target": "x" * 2000}).status_code == 400
    big = client.post("/scans", json={"target": "sample", "scanners": ["source"],
                                      "validation_targets": ["https://127.0.0.1/"] * 201,
                                      "validate": True})
    assert big.status_code == 400
    assert client.post("/plans/verify", json={"before": [{"id": "c1"}] * 5001,
                                              "after": []}).status_code == 400
