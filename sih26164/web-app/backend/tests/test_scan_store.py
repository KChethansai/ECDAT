"""Durable scan store + triage persistence (file-based JSON, stdlib only)."""

import json

import pytest

from app import main, scan_store


@pytest.fixture
def datadir(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_DATA_DIR", str(tmp_path))
    return tmp_path


def _report(target="sample"):
    return {"metadata": {"scanTarget": target},
            "components": [{"id": "a1", "severity": "critical"},
                           {"id": "a2", "severity": "high"}],
            "codeAnalysis": {"findings": [{"id": "c1"}]},
            "migration": {"statuses": {"REQUIRED": 1}}}


def test_save_get_round_trip(datadir):
    record = scan_store.scan_record("abc123", _report(), target="sample")
    scan_store.save_scan(record)
    assert (datadir / "scans" / "abc123.json").is_file()
    back = scan_store.get_scan("abc123")
    assert back["report"]["components"][0]["id"] == "a1"
    assert back["counts"] == {"crypto": 2, "critical": 1, "high": 1,
                              "code": 1, "total": 3}
    assert back["status"] == "complete"


def test_list_latest_previous_order(datadir):
    for sid in ("s1", "s2", "s3"):
        scan_store.save_scan(scan_store.scan_record(sid, _report(target=sid)))
    ids = [e["scan_id"] for e in scan_store.list_scans()]
    assert ids == ["s3", "s2", "s1"]  # newest first
    assert scan_store.get_latest()["scan_id"] == "s3"
    assert scan_store.get_previous()["scan_id"] == "s2"


def test_restart_simulation_reads_disk(datadir):
    scan_store.save_scan(scan_store.scan_record("r1", _report()))
    # No in-memory cache exists: every call below hits the filesystem.
    assert scan_store.get_scan("r1")["id"] == "r1"
    assert [e["scan_id"] for e in scan_store.list_scans()] == ["r1"]


def test_corrupt_record_quarantined_others_survive(datadir):
    scan_store.save_scan(scan_store.scan_record("good", _report()))
    (datadir / "scans" / "bad.json").write_text("{not json", encoding="utf-8")
    assert scan_store.get_scan("bad") is None
    assert list((datadir / "scans").glob("bad.corrupt-*.json"))
    assert not (datadir / "scans" / "bad.json").exists()
    assert scan_store.get_scan("good")["id"] == "good"
    assert [e["scan_id"] for e in scan_store.list_scans()] == ["good"]


def test_corrupt_index_rebuilds(datadir):
    scan_store.save_scan(scan_store.scan_record("k1", _report()))
    (datadir / "scans" / "index.json").write_text("garbage", encoding="utf-8")
    assert [e["scan_id"] for e in scan_store.list_scans()] == ["k1"]


def test_local_and_github_history_shapes(datadir):
    scan_store.save_scan(scan_store.scan_record("loc", _report(), target="sample"))
    gh = _report()
    gh["source"] = {"type": "github", "owner": "o", "repo": "r", "sha": "deadbeef",
                    "ref_requested": "main", "profile": "full"}
    scan_store.save_scan(scan_store.scan_record("gh1", gh, profile="full"))
    by_id = {e["scan_id"]: e for e in scan_store.list_scans()}
    assert by_id["loc"]["source_type"] == "local"
    assert by_id["loc"]["target"] == "sample"
    gh_entry = by_id["gh1"]
    assert (gh_entry["owner"], gh_entry["repo"], gh_entry["sha"]) == ("o", "r", "deadbeef")
    assert gh_entry["profile"] == "full"


def test_duplicate_id_single_entry_latest_wins(datadir):
    scan_store.save_scan(scan_store.scan_record("d", _report(target="one")))
    scan_store.save_scan(scan_store.scan_record("d", _report(target="two")))
    entries = scan_store.list_scans()
    assert [e["scan_id"] for e in entries] == ["d"]
    assert scan_store.get_scan("d")["target"] == "two"


def test_atomic_write_no_tmp_leftovers_and_bad_ids(datadir):
    scan_store.save_scan(scan_store.scan_record("t1", _report()))
    assert not list((datadir / "scans").glob("*.tmp"))
    with pytest.raises(ValueError):
        scan_store.save_scan({"id": "../evil", "report": {}})
    with pytest.raises(ValueError):
        scan_store.save_scan({"id": "", "report": {}})
    assert scan_store.get_scan("../evil") is None
    assert scan_store.get_scan("missing") is None
    assert scan_store.delete_scan("missing") is False


def test_no_secret_keys_introduced(datadir):
    record = scan_store.scan_record("s", _report())
    allowed = {"id", "timestamp", "target", "source", "profile", "status",
               "counts", "migration_summary", "report", "duration_s"}
    assert set(record) <= allowed

def test_delete_scan(datadir):
    scan_store.save_scan(scan_store.scan_record("del", _report()))
    assert scan_store.delete_scan("del") is True
    assert scan_store.get_scan("del") is None
    assert scan_store.list_scans() == []


def test_corrupt_index_then_save_keeps_pointers(datadir):
    scan_store.save_scan(scan_store.scan_record("k1", _report(target="one")))
    scan_store.save_scan(scan_store.scan_record("k2", _report(target="two")))
    (datadir / "scans" / "index.json").write_text("garbage", encoding="utf-8")
    scan_store.save_scan(scan_store.scan_record("k3", _report(target="three")))
    assert sorted(e["scan_id"] for e in scan_store.list_scans()) == ["k1", "k2", "k3"]


def test_retention_evicts_oldest_files(datadir, monkeypatch):
    monkeypatch.setattr(scan_store, "MAX_INDEX", 3)
    for sid in ("e1", "e2", "e3", "e4"):
        scan_store.save_scan(scan_store.scan_record(sid, _report(target=sid)))
    assert sorted(e["scan_id"] for e in scan_store.list_scans()) == ["e2", "e3", "e4"]
    assert not (datadir / "scans" / "e1.json").exists()
    assert scan_store.get_scan("e1") is None


def test_unreadable_file_not_quarantined(datadir):
    scan_store.save_scan(scan_store.scan_record("perm", _report()))
    path = datadir / "scans" / "perm.json"
    path.chmod(0o000)
    try:
        assert scan_store.get_scan("perm") is None
        assert path.is_file()  # left alone: permissions ≠ corruption
        assert not list((datadir / "scans").glob("perm.corrupt-*"))
    finally:
        path.chmod(0o644)


def test_triage_persist_and_legacy_migrate(datadir):
    store = {("s", "f1"): {"scope": "s", "fingerprint": "f1", "status": "triaged",
                           "reason": "", "timestamp": 1.0},
             ("s", "f0"): {"scope": "s", "fingerprint": "f0", "status": "resolved",
                           "reason": "", "timestamp": 0.5}}
    scan_store.save_triage(store)
    back = scan_store.load_triage()
    assert back[("s", "f1")]["status"] == "triaged"
    assert back[("s", "f0")]["status"] == "verified"  # legacy migrated


def test_api_report_delta_history_survive_memory_loss(datadir, monkeypatch):
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    rid = client.post("/scans", json={"target": "sample"}).json()["id"]
    # Simulate a backend restart: drop all process memory.
    main.REPORTS.clear()
    main.SOURCE_HISTORY.clear()
    assert client.get(f"/reports/{rid}").status_code == 200
    same = client.post("/scan-delta", json={"before": rid, "after": rid}).json()
    assert same["summary"]["new"] == 0 and same["summary"]["resolved"] == 0
    history = client.get("/scan-history").json()["history"]
    assert any(h["scan_id"] == rid and h["source_type"] == "local" for h in history)
    main.REPORTS.clear()
    main.SOURCE_HISTORY.clear()


def test_api_triage_survives_memory_loss(datadir, monkeypatch):
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    rid = client.post("/scans", json={"target": "sample"}).json()["id"]
    fp = client.get(f"/reports/{rid}").json()["components"][0]["fp"]
    scope = "local:sample"
    assert client.post("/triage", json={"scope": scope, "fingerprint": fp,
                                        "status": "in_progress"}).status_code == 200
    assert client.post("/triage", json={"scope": scope, "fingerprint": fp,
                                        "status": "suppressed",
                                        "reason": ""}).status_code == 400
    # Simulate restart: drop memory, force reload from disk.
    main.TRIAGE.clear()
    main._TRIAGE_LOADED = False
    listed = client.get("/triage", params={"scope": scope}).json()["triage"]
    assert any(e["status"] == "in_progress" for e in listed)
    main.REPORTS.clear()
    main.SOURCE_HISTORY.clear()
    main.TRIAGE.clear()
    main._TRIAGE_LOADED = False
