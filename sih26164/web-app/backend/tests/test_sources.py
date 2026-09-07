"""GitHub source acquisition: URL parsing, safe fetch/extract, pipeline equivalence.

No live network: tarballs are built in-test; urlopen is monkeypatched.
"""

import gzip
import io
import json
import tarfile
import tempfile
from pathlib import Path

import pytest

from app.sources import (AcquisitionError, AcquisitionPolicy, candidate_archives,
                         delta, extract_archive, history_record, isolated_workspace,
                         parse_github_url, relativize_report, resolve_profile,
                         resolve_ref, set_triage, topdir_sha)
from app.sources import acquire as acquire_mod

SHA = "a" * 40


@pytest.fixture(autouse=True)
def _stable_dns(monkeypatch):
    """Deterministic DNS: public IP for any host (no real resolution in tests).

    The routability logic itself is covered by _assert_routable_host unit tests
    below; this keeps fetch-path tests independent of network/DNS flakes.
    """
    import socket as _socket

    def _fake(host, port, type=None, *args, **kwargs):
        name = str(host or "").lower().rstrip(".")
        ip = "127.0.0.1" if name in ("localhost", "127.0.0.1", "::1") else "140.82.114.22"
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr("socket.getaddrinfo", _fake)


def test_routable_host_refusals():
    from app.sources.acquire import _assert_routable_host

    assert _assert_routable_host("codeload.github.com", {"codeload.github.com"})
    with pytest.raises(AcquisitionError):
        _assert_routable_host("evil.com", {"codeload.github.com"})
    with pytest.raises(AcquisitionError):
        _assert_routable_host("localhost", {"localhost", "codeload.github.com"})


def _tarball(files: dict[str, bytes], topdir: str = f"repo-{SHA}") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"{topdir}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture()
def repo_body():
    return _tarball({
        "app.py": b"import hashlib\nh = hashlib.md5(b'x')\n",
        "lib/util.py": b"def helper():\n    return 1\n",
        "requirements.txt": b"requests==2.31\n",
    })


# --- URL parsing ---------------------------------------------------------------

def test_valid_url_forms():
    base = parse_github_url("https://github.com/psf/requests")
    assert (base["owner"], base["repo"], base["ref"]) == ("psf", "requests", None)
    assert parse_github_url("https://github.com/psf/requests/")["repo"] == "requests"
    assert parse_github_url("https://github.com/psf/requests.git")["repo"] == "requests"
    tree = parse_github_url("https://github.com/psf/requests/tree/main")
    assert (tree["ref"], tree["ref_kind"]) == ("main", "branch")
    assert parse_github_url("https://github.com/o/r/tree/feature/x")["ref"] == "feature/x"
    commit = parse_github_url(f"https://github.com/o/r/commit/{SHA}")
    assert (commit["ref"], commit["ref_kind"]) == (SHA, "commit")
    tag = parse_github_url("https://github.com/o/r/releases/tag/v1.0")
    assert (tag["ref"], tag["ref_kind"]) == ("v1.0", "tag")


def test_malicious_and_malformed_urls_rejected():
    bad = ["http://github.com/o/r", "https://evil.com/o/r",
           "https://github.com.evil.com/o/r", "https://127.0.0.1/o/r",
           "https://localhost/o/r", "https://user:pass@github.com/o/r",
           "https://github.com/o", "https://github.com/o/r/pull/5",
           "https://github.com/o/r/archive/refs/heads/main.zip",
           "https://github.com/o/r/commit/short", "not a url", "",
           "https://github.com:8443/o/r", "ftp://github.com/o/r",
           "https://github.com/o/../x", "file:///etc/passwd"]
    for url in bad:
        with pytest.raises(ValueError):
            parse_github_url(url)


# --- ref resolution --------------------------------------------------------------

class _FakeResp:
    def __init__(self, body: bytes, url: str, status: int = 200, headers=None):
        self._body, self.url, self.status = body, url, status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        if not self._body:
            return b""
        chunk, self._body = self._body[:n], self._body[n:]
        return chunk


def _fake_urlopen(responses):
    def fake(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url not in responses:
            raise OSError(f"unexpected fetch: {url}")
        return responses[url]()
    return fake


def test_explicit_sha_needs_no_network():
    policy = AcquisitionPolicy()
    resolved = resolve_ref("o", "r", SHA, "commit", policy, 9999999999.0)
    assert resolved["sha"] == SHA and resolved["via"] == "explicit-sha"


def test_api_success_and_private_rejected(monkeypatch):
    policy = AcquisitionPolicy()
    commit_body = json.dumps({"sha": SHA}).encode()
    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        "https://api.github.com/repos/o/r/commits/main":
            lambda: _FakeResp(commit_body, "https://api.github.com/x"),
    }))
    resolved = resolve_ref("o", "r", "main", "branch", policy, 9999999999.0)
    assert resolved["sha"] == SHA and resolved["via"] == "api"
    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        "https://api.github.com/repos/o/r":
            lambda: _FakeResp(json.dumps({"default_branch": "main", "private": True}).encode(), "u"),
    }))
    with pytest.raises(AcquisitionError):
        resolve_ref("o", "r", None, None, policy, 9999999999.0)


def test_api_failure_falls_back(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("no network")
    monkeypatch.setattr(acquire_mod, "urlopen", boom)
    resolved = resolve_ref("o", "r", "main", "branch", AcquisitionPolicy(), 9999999999.0)
    assert resolved["via"] == "archive-probe" and resolved["sha"] == ""


def test_candidate_archive_order():
    assert candidate_archives("o", "r", {"via": "explicit-sha", "sha": SHA}) == \
        [f"https://codeload.github.com/o/r/tar.gz/{SHA}"]
    cands = candidate_archives("o", "r", {"via": "archive-probe", "requested_ref": "dev"})
    assert cands[0].endswith("/tar.gz/dev")
    assert any("refs/heads/dev" in c for c in cands)
    assert candidate_archives("o", "r", {"requested_ref": ""})[0].endswith("refs/heads/main")


# --- fetch safety -----------------------------------------------------------------

def _policy(**over):
    base = {"max_download_bytes": 1048576, "max_extracted_bytes": 10485760,
            "max_files": 1000, "total_deadline_s": 60}
    base.update(over)
    return AcquisitionPolicy(base)


def test_fetch_success_and_404_and_evil_redirect(monkeypatch, repo_body):
    from app.sources.acquire import fetch_bytes

    good = "https://codeload.github.com/o/r/tar.gz/main"
    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        good: lambda: _FakeResp(repo_body, good),
        "https://codeload.github.com/o/nope/tar.gz/main":
            lambda: _FakeResp(b"{}", "u", status=404),
        "https://codeload.github.com/o/redir/tar.gz/main":
            lambda: _FakeResp(b"", "u", status=302, headers={"Location": "https://evil.com/x"}),
        "https://codeload.github.com/o/priv/tar.gz/main":
            lambda: _FakeResp(b"", "u", status=403),
    }))
    body, final = fetch_bytes(good, _policy(), 9999999999.0)
    assert body == repo_body and final == good
    with pytest.raises(AcquisitionError):
        fetch_bytes("https://codeload.github.com/o/nope/tar.gz/main", _policy(), 9999999999.0)
    with pytest.raises(AcquisitionError):
        fetch_bytes("https://codeload.github.com/o/redir/tar.gz/main", _policy(), 9999999999.0)
    with pytest.raises(AcquisitionError):
        fetch_bytes("https://codeload.github.com/o/priv/tar.gz/main", _policy(), 9999999999.0)
    with pytest.raises(AcquisitionError):
        fetch_bytes("https://evil.com/x", _policy(), 9999999999.0)


def test_fetch_oversize_and_timeout(monkeypatch):
    from app.sources.acquire import fetch_bytes

    big = "https://codeload.github.com/o/big/tar.gz/main"
    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        big: lambda: _FakeResp(b"x" * 100, big),
    }))
    with pytest.raises(AcquisitionError):  # expired deadline
        fetch_bytes(big, _policy(), 0.0)
    huge = "https://codeload.github.com/o/huge/tar.gz/main"
    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        huge: lambda: _FakeResp(b"x" * (2 * 1048576), huge),
    }))
    tiny = AcquisitionPolicy({"max_download_bytes": 1048576,
                              "max_extracted_bytes": 10485760,
                              "max_files": 1000, "total_deadline_s": 60})
    with pytest.raises(AcquisitionError):
        fetch_bytes(huge, tiny, 9999999999.0)


# --- archive safety -----------------------------------------------------------------

def test_extract_happy_path_and_sha(tmp_path, repo_body):
    dest = tmp_path / "ws"
    dest.mkdir()
    topdir, skipped = extract_archive(repo_body, dest, _policy())
    assert topdir == f"repo-{SHA}" and skipped == 0
    assert topdir_sha(topdir, "repo") == SHA
    assert (dest / topdir / "app.py").is_file()


def _raw_tar(members: list[tuple[str, bytes, str]]) -> bytes:
    """members: (name, data, kind=file|symlink|dir)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data if isinstance(data, str) else data.decode()
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract_rejects_hostile_archives(tmp_path):
    dest = tmp_path / "ws"
    dest.mkdir()
    hostile = [
        _raw_tar([("../evil.py", b"x", "file")]),
        _raw_tar([("/abs.py", b"x", "file")]),
        _raw_tar([("a/../../evil.py", b"x", "file")]),
        b"not a gzip at all",
        gzip.compress(b"not a tar"),
    ]
    for body in hostile:
        with pytest.raises(AcquisitionError):
            extract_archive(body, dest, _policy())
    multi = _raw_tar([("top-a/x.py", b"x", "file"), ("top-b/y.py", b"y", "file")])
    with pytest.raises(AcquisitionError):
        extract_archive(multi, dest, _policy())


def test_extract_drops_symlinks_and_enforces_limits(tmp_path, monkeypatch):
    dest = tmp_path / "ws"
    dest.mkdir()
    body = _raw_tar([("top/x.py", b"x", "file"), ("top/link.py", "x.py", "symlink")])
    topdir, skipped = extract_archive(body, dest, _policy())
    assert skipped == 1 and not (dest / topdir / "link.py").exists()
    many = _raw_tar([(f"top/f{i}.py", b"x", "file") for i in range(101)])
    with pytest.raises(AcquisitionError):
        extract_archive(many, dest, _policy(max_files=100))
    monkeypatch.setattr(acquire_mod, "MAX_SINGLE_FILE_BYTES", 50)
    big = _raw_tar([("top/big.bin", b"x" * 100, "file")])
    with pytest.raises(AcquisitionError):
        extract_archive(big, dest, _policy())


def test_workspace_cleanup_on_failure(tmp_path):
    import app.sources.acquire as acquire

    before = set(Path(tempfile.gettempdir()).glob("ecdat-src-*"))
    with pytest.raises(AcquisitionError):
        with acquire.isolated_workspace() as workspace:
            assert workspace.is_dir()
            assert workspace.parent == Path(tempfile.gettempdir())
            raise AcquisitionError("boom")
    after = set(Path(tempfile.gettempdir()).glob("ecdat-src-*"))
    assert after <= before


# --- profiles / history / triage -------------------------------------------------------

def test_profiles_and_unknown():
    assert resolve_profile("quick", None, False, False)["scanners"] == \
        ["source", "dependency", "binary"]
    assert resolve_profile("crypto", None, False, False)["code_analysis"] is False
    assert resolve_profile("full", None, False, False)["code_analysis"] is True
    assert resolve_profile("full", None, False, True)["validate"] is True
    assert resolve_profile("full", ["source"], False, False)["scanners"] == ["source"]
    with pytest.raises(ValueError):
        resolve_profile("nope", None, False, False)


def test_delta_and_triage():
    from app.sources.history import apply_triage

    before = {"components": [{"id": "a1", "fp": "f1", "algorithm": "RSA"},
                             {"id": "a2", "fp": "f2", "algorithm": "MD5"}],
              "codeAnalysis": {"findings": [{"id": "c1", "fp": "g1", "title": "t"}]}}
    after = {"components": [{"id": "a1", "fp": "f1", "algorithm": "RSA"},
                            {"id": "a3", "fp": "f3", "algorithm": "AES"}],
             "codeAnalysis": {"findings": [{"id": "c1x", "fp": "g1", "title": "t"}]}}
    result = delta(before, after)
    assert {e["id"] for e in result["resolved"]} == {"a2"}
    assert {e["id"] for e in result["new"]} == {"a3"}
    assert {e["id"] for e in result["unchanged"]} == {"a1"}
    assert [(e["id"], e.get("after_id")) for e in result["changed"]] == [("c1", "c1x")]
    store: dict = {}
    entry = set_triage(store, "github:o/r", "f2", "suppressed", "false-positive")
    assert entry["status"] == "suppressed"
    with pytest.raises(ValueError):
        set_triage(store, "github:o/r", "f2", "suppressed", "")
    with pytest.raises(ValueError):
        set_triage(store, "github:o/r", "f2", "bogus")
    apply_triage(before["components"], store, "github:o/r")
    assert before["components"][1]["triage"]["status"] == "suppressed"
    assert before["components"][0]["triage"] == {"status": "open", "reason": ""}
    # evidence untouched by triage
    assert before["components"][1]["algorithm"] == "MD5"
    record = history_record("rid1", {"type": "github", "owner": "o", "repo": "r",
                                     "sha": SHA, "ref_requested": "main"},
                            "full", before, 1.5)
    assert record["counts"] == {"crypto": 2, "critical": 0, "code": 1}


# --- relativization -----------------------------------------------------------------------

def test_relativize_recomputes_ids_and_fps(tmp_path, repo_body):
    from app.pipeline import run_scan

    from app.sources.normalize import rekey_code, rekey_crypto

    dest = tmp_path / "ws"
    dest.mkdir()
    topdir, _ = extract_archive(repo_body, dest, _policy())
    root = dest / topdir
    report = run_scan(root, ["source", "dependency"], code_analysis=True,
                      code_categories=["dead_code"])
    assert any("/tmp" in c["file_path"] or str(tmp_path) in c["file_path"]
               for c in report["components"])
    prefix = relativize_report(report, root, "o", "r", SHA)
    assert prefix == "o/r"  # sha-free: ids stay stable across commits
    assert all(c["file_path"].startswith(prefix) for c in report["components"])
    assert all("fp" in c for c in report["components"])
    assert all(str(tmp_path) not in c["file_path"] for c in report["components"])
    # ids match what the dataclasses compute for the logical path (no drift)
    sample = next(c for c in report["components"] if c["scanner"] == "source")
    check = dict(sample)
    rekey_crypto(check, sample["file_path"])
    assert check["id"] == sample["id"]
    code = (report.get("codeAnalysis") or {}).get("findings", [])
    assert code and all(f["file_path"].startswith(prefix) for f in code)
    check_code = dict(code[0])
    rekey_code(check_code, code[0]["file_path"])
    assert check_code["id"] == code[0]["id"]
    # determinism: same logical report twice
    again = run_scan(root, ["source", "dependency"], code_analysis=True,
                     code_categories=["dead_code"])
    relativize_report(again, root, "o", "r", SHA)
    strip = lambda r: sorted((c["id"], c["fp"]) for c in r["components"])
    assert strip(report) == strip(again)


# --- pipeline equivalence -------------------------------------------------------------------

def test_local_vs_github_equivalence(monkeypatch, tmp_path, repo_body):
    from app.pipeline import run_github_scan, run_scan

    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        f"https://codeload.github.com/o/r/tar.gz/{SHA}":
            lambda: _FakeResp(repo_body, "u"),
    }))
    local = tmp_path / "local"
    local.mkdir()
    topdir = f"repo-{SHA}"
    (local / "app.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    (local / "lib").mkdir()
    (local / "lib" / "util.py").write_text("def helper():\n    return 1\n")
    (local / "requirements.txt").write_text("requests==2.31\n")
    local_report = run_scan(local, ["source", "dependency"], code_analysis=True,
                            code_categories=["dead_code"])
    github_report = run_github_scan(f"https://github.com/o/r/commit/{SHA}", None, "full",
                                    ["source", "dependency"], code_analysis=True,
                                    code_categories=["dead_code"])
    assert github_report["source"]["sha"] == SHA
    assert github_report["source"]["profile"] == "full"
    assert github_report["metadata"]["scanTarget"] == f"github:o/r@{SHA[:12]}"
    sig = lambda r: sorted((c["algorithm"], c["category"], c["line"], c.get("severity"))
                           for c in r["components"])
    assert sig(local_report) == sig(github_report)
    code_sig = lambda r: sorted((f["title"], f["line"]) for f in
                                (r.get("codeAnalysis") or {}).get("findings", []))
    assert code_sig(local_report) == code_sig(github_report)
    import json as _json
    _json.dumps(github_report)


# --- API --------------------------------------------------------------------------

def test_api_remote_scan_validation_and_history(monkeypatch, repo_body):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setattr(acquire_mod, "urlopen", _fake_urlopen({
        f"https://codeload.github.com/o/r/tar.gz/{SHA}":
            lambda: _FakeResp(repo_body, "u"),
    }))
    client = TestClient(app)
    # ambiguous: source + non-default target
    assert client.post("/scans", json={"target": "other",
                                       "source": {"type": "github",
                                                  "url": "https://github.com/o/r"}}).status_code == 400
    # bad source type / bad url / bad profile
    assert client.post("/scans", json={"source": {"type": "gitlab",
                                                  "url": "https://x/y"}}).status_code == 400
    assert client.post("/scans", json={"source": {"type": "github",
                                                  "url": "https://evil.com/o/r"}}).status_code == 400
    assert client.post("/scans", json={"source": {"type": "github",
                                                  "url": "https://github.com/o/r"},
                                       "profile": "nope"}).status_code == 400
    body = client.post("/scans", json={"source": {"type": "github",
                                                  "url": f"https://github.com/o/r/commit/{SHA}"},
                                       "profile": "quick"}).json()
    report = body["report"]
    assert report["source"]["sha"] == SHA
    assert report["source"]["profile"] == "quick"
    assert report["metadata"]["scanTarget"] == f"github:o/r@{SHA[:12]}"
    assert all("o/r/" in c["file_path"] for c in report["components"])
    history = client.get("/scan-history").json()["history"]
    assert any(h["sha"] == SHA and h["profile"] == "quick" for h in history)
    same = client.post("/scan-delta", json={"before": body["id"],
                                            "after": body["id"]}).json()
    assert same["summary"]["resolved"] == 0 and same["summary"]["new"] == 0
    code_total = len((report.get("codeAnalysis") or {}).get("findings", []))
    assert same["summary"]["unchanged"] == len(report["components"]) + code_total
    assert all("/repo-" not in c["file_path"] for c in report["components"])
    assert client.post("/scan-delta", json={"before": "nope",
                                            "after": body["id"]}).status_code == 404
    # triage round-trip
    fp = report["components"][0]["fp"]
    scope = "github:o/r"
    assert client.post("/triage", json={"scope": scope, "fingerprint": fp,
                                        "status": "suppressed",
                                        "reason": ""}).status_code == 400
    entry = client.post("/triage", json={"scope": scope, "fingerprint": fp,
                                         "status": "suppressed",
                                         "reason": "false-positive"}).json()
    assert entry["status"] == "suppressed"
    fetched = client.get(f"/reports/{body['id']}").json()
    assert fetched["components"][0]["triage"]["status"] == "suppressed"
    assert client.get("/triage", params={"scope": scope}).json()["triage"]
    # sarif carries repo/commit context
    sarif = client.get(f"/reports/{body['id']}/sarif").json()
    assert sarif["runs"][0]["versionControlProvenance"][0]["revisionId"] == SHA
