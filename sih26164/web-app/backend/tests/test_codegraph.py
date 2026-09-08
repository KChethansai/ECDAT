"""Codebase knowledge graph: unified model, projections, vault, determinism."""

import json

import pytest

from app import codegraph as cg


@pytest.fixture()
def repo(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "signer.py").write_text(
        "import hashlib\nRSA_BITS = 2048\n\ndef sign(data):\n"
        "    return hashlib.sha256(data).digest()\n")
    (tmp_path / "pkg" / "auth.py").write_text(
        "from pkg.signer import sign\n\ndef login(user):\n"
        "    return sign(user.encode())\n")
    (tmp_path / "pkg" / "cli.py").write_text(
        'if __name__ == "__main__":\n    print("hi")\n')
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text(
        "from pkg.auth import login\n\ndef test_login():\n"
        "    assert login('a')\n")
    (tmp_path / "security.yaml").write_text("key_bits: 2048\n")
    return tmp_path


def _ctx(repo, **kw):
    kw.setdefault("scan_id", "t1")
    return cg.build_context(repo, **kw)


# -- model --------------------------------------------------------------------

def test_stable_ids_and_types(repo):
    ctx = _ctx(repo)
    assert "file:pkg/auth.py" in ctx.nodes
    assert "symbol:pkg/auth.py#login" in ctx.nodes
    assert ctx.nodes["symbol:pkg/auth.py#login"]["type"] == "FUNCTION"
    edge = next(r for r in ctx.relationships
                if r["source"] == "file:pkg/auth.py"
                and r["target"] == "file:pkg/signer.py"
                and r["type"] == "IMPORTS")
    assert edge["confidence"] == "HIGH" and edge["evidence"]
    assert _ctx(repo).to_dict() == ctx.to_dict()


def test_no_low_confidence_edges_emitted(repo):
    ctx = _ctx(repo)
    assert all(r["confidence"] in ("HIGH", "MEDIUM") for r in ctx.relationships)
    assert all(r["evidence"] for r in ctx.relationships)


def test_duplicate_prevention(repo):
    ctx = _ctx(repo)
    n, m = len(ctx.nodes), len(ctx.relationships)
    ctx.add_node(next(iter(ctx.nodes.values())))
    for rel in list(ctx.relationships):
        ctx.add_rel(dict(rel))
    assert (len(ctx.nodes), len(ctx.relationships)) == (n, m)


def test_entry_point_and_tests(repo):
    ctx = _ctx(repo)
    assert any(n["type"] == "ENTRY_POINT" for n in ctx.nodes.values())
    assert any(r["type"] == "TESTS" and r["target"] == "file:pkg/auth.py"
               for r in ctx.relationships)


# -- blast radius / planner ----------------------------------------------------

def _report():
    return {"components": [
        {"id": "c1", "scanner": "source", "algorithm": "RSA",
         "category": "asymmetric", "file_path": "pkg/signer.py", "line": 2,
         "severity": "critical", "is_mock": False}]}


def test_blast_radius_buckets_with_evidence(repo):
    ctx = _ctx(repo, report=_report())
    blast = cg.blast_radius(ctx, "c1")
    assert blast["status"] == "KNOWN"
    surf = blast["affected_surface"]
    assert any(e["path"] == "pkg/signer.py"
               for e in surf["DIRECTLY_AFFECTED"])
    assert any(e["path"] == "pkg/auth.py" for e in surf["DIRECTLY_AFFECTED"])
    assert any(e["path"] == "tests/test_auth.py" for e in surf["TEST_AFFECTED"])
    for entries in surf.values():
        for entry in entries:
            assert entry["reason"] and entry["relationship"] and entry["confidence"]


def test_blast_radius_unknown(repo):
    ctx = _ctx(repo)
    assert cg.blast_radius(ctx, "nope")["status"] == "UNKNOWN"


def test_plan_uses_surface_and_validates(repo):
    from app.code_analysis import build_plan, finding_from_dict

    ctx = _ctx(repo, report=_report())
    blast = cg.blast_radius(ctx, "c1")
    raw = {"id": "cf1", "analyzer": "dead_code", "category": "DEAD_CODE",
           "file_path": "pkg/signer.py", "line": 2, "symbol": "sign",
           "title": "x", "description": "d", "evidence": "e",
           "confidence": "HIGH", "verdict": "OBSERVATION", "impact": "MEDIUM",
           "rationale": "r", "verification": "v",
           "remediation_options": [{"option_id": "remove", "title": "Remove",
                                    "description": "d", "affected_files": ["pkg/signer.py"],
                                    "advantages": [], "disadvantages": [],
                                    "verification": [], "complexity": "LOW",
                                    "risk": "LOW", "reversibility": "yes",
                                    "automation_suitability": "HIGH",
                                    "compatibility": [], "prerequisites": []}]}
    plan = build_plan(finding_from_dict(raw), "remove",
                      context={"affected_surface": blast["affected_surface"]})
    assert "pkg/auth.py" in plan["affected_files"]
    assert any(t["relationship"] == "CALLS" for t in plan["traceability"])
    assert plan["context_validated"] is True
    assert cg.validate_plan(plan, ctx)["valid"] is True
    bad = dict(plan, affected_files=["gone/missing.py"])
    assert cg.validate_plan(bad, ctx)["verdict"] == "PLAN INVALID"


def test_plan_without_context_unchanged(repo):
    from app.code_analysis import build_plan, finding_from_dict

    raw = {"id": "cf1", "analyzer": "dead_code", "category": "DEAD_CODE",
           "file_path": "pkg/signer.py", "line": 2, "symbol": "s",
           "title": "x", "description": "d", "evidence": "e",
           "confidence": "HIGH", "verdict": "OBSERVATION", "impact": "MEDIUM",
           "rationale": "r", "verification": "v",
           "remediation_options": [{"option_id": "remove", "title": "Remove",
                                    "description": "d", "affected_files": ["pkg/only.py"],
                                    "advantages": [], "disadvantages": [],
                                    "verification": [], "complexity": "LOW",
                                    "risk": "LOW", "reversibility": "yes",
                                    "automation_suitability": "HIGH",
                                    "compatibility": [], "prerequisites": []}]}
    plan = build_plan(finding_from_dict(raw), "remove")
    assert plan["affected_files"] == ["pkg/only.py"]
    assert plan["traceability"] == [] and plan["context_validated"] is False


# -- canvas / obsidian ----------------------------------------------------------

def test_canvas_valid_and_deterministic(repo):
    ctx = _ctx(repo, report=_report())
    first, second = cg.canvas(ctx), cg.canvas(ctx)
    assert first == second
    assert first["nodes"] and first["metadata"]["node_count"] <= 60
    with pytest.raises(ValueError):
        cg.canvas(ctx, "bogus")


def test_vault_write_idempotent_and_collision_safe(repo, tmp_path):
    ctx = _ctx(repo, report=_report())
    first = cg.to_vault(ctx, tmp_path)
    assert first["notes"] and first["canvases"]
    second = cg.to_vault(ctx, tmp_path)
    assert second["collisions"] == []  # managed notes compare identical
    assert (tmp_path / first["canvases"][0]).is_file()
    void = json.loads((tmp_path / first["canvases"][0]).read_text())
    assert void["nodes"] and all("id" in n for n in void["nodes"])
    # user note collision: kept, ECDAT writes aside, collision recorded
    victim = tmp_path / first["notes"][0]
    victim.write_text("# mine\n")
    third = cg.to_vault(ctx, tmp_path)
    assert third["collisions"] and victim.read_text() == "# mine\n"


def test_vault_finding_contexts(repo, tmp_path):
    ctx = _ctx(repo, report=_report())
    manifest = cg.to_vault(ctx, tmp_path)
    assert manifest["finding_contexts"]
    assert "omitted" in manifest and "entity_notes" in manifest["omitted"]


def test_prune_keeps_newest_and_skips_foreign(tmp_path):
    for name in ("s1", "s2", "s3"):
        scope = tmp_path / "Graphs" / name
        scope.mkdir(parents=True)
        (scope / "n.md").write_text("---\nmanaged_by: ECDAT\ngenerated: true\n---\n")
    foreign = tmp_path / "Graphs" / "a0"
    foreign.mkdir(parents=True)
    (foreign / "n.md").write_text("# user note\n")
    out = cg.prune_snapshots(tmp_path, keep=2)
    assert out["removed"] == ["s1"] and out["skipped"] == ["a0"]
    assert (tmp_path / "Graphs" / "a0" / "n.md").is_file()


# -- delta / health / limits -------------------------------------------------------

def test_diff_graphs(repo):
    before = cg.component_graph(_ctx(repo))
    (repo / "pkg" / "newmod.py").write_text("X = 1\n")
    (repo / "pkg" / "auth.py").write_text(
        (repo / "pkg" / "auth.py").read_text() + "\n# touched\n")
    after = cg.component_graph(_ctx(repo))
    delta = cg.diff_graphs(before, after)
    assert delta["added_nodes"] == ["file:pkg/newmod.py"]
    assert "file:pkg/auth.py" in delta["changed_nodes"]
    assert delta["removed_nodes"] == [] and "before_scan" in delta


def test_limits_reported_explicitly(repo, monkeypatch):
    monkeypatch.setitem(cg.LIMITS, "notes", 1)
    monkeypatch.setitem(cg.LIMITS, "canvas_nodes", 2)
    ctx = _ctx(repo, report=_report())
    comp = cg.component_graph(ctx)
    assert comp["truncation"].get("nodes_capped", {}).get("limit", 800) == 800
    manifest = cg.to_vault(ctx, repo / "vault-out")
    assert manifest["omitted"]["entity_notes"] >= 1
    void = cg.canvas(ctx)
    assert void["metadata"]["truncated"] is True or len(void["nodes"]) <= 2


def test_health_and_limits(repo):
    ctx = _ctx(repo)
    assert cg.health(ctx)["status"] == "PASS"
    assert set(cg.BUCKETS) == {"DIRECTLY_AFFECTED", "INDIRECTLY_AFFECTED",
                               "TEST_AFFECTED", "CONFIGURATION_AFFECTED",
                               "DEPENDENCY_AFFECTED", "API_AFFECTED",
                               "OPTIONAL_REVIEW"}


def test_determinism_across_seeds(repo):
    first = cg.component_graph(_ctx(repo, report=_report()))
    second = cg.component_graph(_ctx(repo, report=_report()))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_no_separate_ast_parse_and_no_low_edges(repo):
    import pathlib

    src = pathlib.Path("app/codegraph.py").read_text()
    assert "ast.parse" not in src  # reuses symbols.build_graph
    ctx = _ctx(repo)
    assert all(r["confidence"] != "LOW" for r in ctx.relationships)


def test_secret_strings_redacted_in_evidence(tmp_path):
    (tmp_path / "m.py").write_text('KEY = "x"\nimport os\ncfg = "api_key: abc123"\n')
    ctx = cg.build_context(tmp_path, scan_id="sec")
    blob = __import__("json").dumps(ctx.to_dict())
    assert "abc123" not in blob
