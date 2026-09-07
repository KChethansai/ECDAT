"""Minimal SARIF 2.1.0 writer for ECDAT findings + validation context (stdlib json)."""

from __future__ import annotations

SEVERITY_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SEVERITY_SCORE = {"critical": "9.0", "high": "7.5", "medium": "5.0", "low": "2.5"}


def _rule_id(finding: dict) -> str:
    algo = str(finding.get("algorithm") or "unknown").replace(" ", "-")
    return f"ECDAT-{algo}"


def to_sarif(report: dict, validations: list[dict] | None = None) -> dict:
    components = report.get("components", []) if isinstance(report, dict) else []
    source = report.get("source") or {} if isinstance(report, dict) else {}
    source_label = ""
    if isinstance(source, dict) and source.get("type") == "github":
        source_label = (f"{source.get('owner')}/{source.get('repo')}"
                        f"@{(source.get('sha') or '')[:12]}")
    by_finding: dict[str, list[dict]] = {}
    for res in validations or []:
        if res.get("finding_id"):
            by_finding.setdefault(res["finding_id"], []).append(res)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for row in components:
        rid = _rule_id(row)
        sev = str(row.get("severity") or "low")
        rules.setdefault(rid, {
            "id": rid, "name": f"Crypto usage: {row.get('algorithm', 'unknown')}",
            "shortDescription": {"text": f"{row.get('algorithm', '?')} ({row.get('category', '?')})"},
            "fullDescription": {"text": str(row.get("rationale") or "")[:1000]},
            "properties": {"security-severity": SEVERITY_SCORE.get(sev, "2.5")}})
        loc = {"physicalLocation": {"artifactLocation": {
            "uri": str(row.get("file_path") or "unknown")[:512]},
            "region": {"startLine": max(int(row.get("line") or 1), 1)}}}
        props: dict = {"ecdat": {
            "finding_id": row.get("id"), "severity": sev,
            "validationStatus": row.get("validationStatus", "STATIC_ONLY"),
            "is_mock": bool(row.get("is_mock"))}}
        if source_label:
            props["ecdat"]["source"] = source_label
        for res in by_finding.get(row.get("id", ""), [])[:5]:
            props.setdefault("validations", []).append({
                "validation_id": res.get("validation_id"), "status": res.get("status"),
                "type": res.get("validation_type"),
                "observed": {k: res.get(k) for k in
                             ("observed_algorithm", "observed_protocol",
                              "observed_cipher", "observed_key_size")}})
        results.append({"ruleId": rid, "level": SEVERITY_LEVEL.get(sev, "note"),
                        "message": {"text": str(row.get("rationale") or row.get("algorithm"))[:1000]},
                        "locations": [loc], "properties": props})
    run: dict = {"tool": {"driver": {"name": "ECDAT", "version": "0.1.0",
                                           "rules": sorted(rules.values(), key=lambda r: r["id"])}},
                   "results": results}
    source = report.get("source") or {} if isinstance(report, dict) else {}
    if isinstance(source, dict) and source.get("type") == "github" and source.get("sha"):
        run["versionControlProvenance"] = [{
            "repositoryUri": source.get("canonical_url", ""),
            "revisionId": source.get("sha", ""),
            "properties": {"ecdat": {
                "ref_requested": source.get("ref_requested", ""),
                "profile": source.get("profile", "")}}}]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [run]}
