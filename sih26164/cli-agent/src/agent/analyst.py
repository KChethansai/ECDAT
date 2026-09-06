"""AI-assisted analyst layer (Phase 15). Deterministic evidence in, advisory answers out.

Architecture: deterministic ECDAT analysis -> structured brief -> analyst answer.
The LOCAL renderer answers from report facts without any provider (always works
offline). An external provider (via existing adapters) may add INTERPRETATION
only; FACT sections always come from the report. Vault notes are untrusted
context: they never alter facts, scores, or findings, and are never executed.

Every answer separates FACT (report-backed), INTERPRETATION (reasoned), and
UNKNOWN (not in evidence). Nothing here mutates the report.
"""

from __future__ import annotations

MAX_BRIEF_CHARS = 6000


def _truncate(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "…"


def _top(report: dict, n: int = 5) -> list[dict]:
    rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    return sorted(report.get("components", []),
                  key=lambda c: (rank.get(c.get("priority", "P3"), 3), c.get("id", "")))[:n]


def build_brief(report: dict, max_chars: int = MAX_BRIEF_CHARS) -> str:
    """Compact structured evidence digest. Bounded, secret-free (reports are redacted)."""
    summary = report.get("summary", {})
    inventory = (report.get("intelligence") or {}).get("inventory", [])
    migration = report.get("migration") or {}
    scanners = ", ".join((report.get("metadata") or {}).get("scannerSources", []))
    lines = [
        f"Scope: {((report.get('metadata') or {}).get('scanTarget', 'unknown'))}",
        f"Findings: {summary.get('total', 0)} "
        f"(critical={summary.get('bySeverity', {}).get('critical', 0)}, "
        f"high={summary.get('bySeverity', {}).get('high', 0)})",
        f"Scanners: {scanners or 'unknown'}",
        f"Families: {len(inventory)}",
    ]
    for row in inventory[:8]:
        lines.append(f"- {row.get('family')}: {row.get('priority')} "
                     f"({row.get('findingCount')} findings; {row.get('recommendation', '')[:80]})")
    lines.append("Top findings:")
    for finding in _top(report):
        lines.append(f"- {finding.get('priority')} {finding.get('algorithm')} "
                     f"[{finding.get('scanner')}] {_truncate(finding.get('rationale', ''), 160)}")
    roadmap = migration.get("roadmap", {})
    lines.append("Migration: " + ", ".join(
        f"{bucket}={len(roadmap.get(bucket, []))}"
        for bucket in ("Immediate", "Near-term", "Planned", "Monitor")))
    unknowns = ((migration.get("report") or {}).get("unknowns", []))
    if unknowns:
        lines.append("Unknowns: " + "; ".join(unknowns))
    return "\n".join(lines)[:max_chars]


def summarize(report: dict) -> str:
    """Scan summary with FACT / INTERPRETATION / UNKNOWN separation."""
    brief = build_brief(report)
    migration = report.get("migration") or {}
    top_item = (migration.get("workItems") or [{}])[0]
    return "\n".join([
        "## FACT (from this scan's deterministic report)",
        brief,
        "",
        "## INTERPRETATION (reasoned, advisory)",
        (f"Highest leverage: {top_item.get('title', 'none')} — "
         f"{_truncate(top_item.get('reason', ''), 200)}"
         if top_item.get("title") else "No migration candidates in this scan."),
        "Priorities reflect migration urgency under the Mosca heuristic, not predictions.",
        "",
        "## UNKNOWN (not in evidence)",
        "Runtime coverage beyond controlled observations; vulnerability status; "
        "migration completion; business criticality.",
    ])


def explain_finding(report: dict, finding_id: str) -> str:
    """Explain one finding from its actual factors. Raises KeyError when absent."""
    finding = next((c for c in report.get("components", []) if c.get("id") == finding_id), None)
    if finding is None:
        raise KeyError(f"unknown finding id: {finding_id}")
    related = finding.get("related", [])
    runtime = [r for r in related if r.get("relation") == "runtime-observed"]
    return "\n".join([
        "## FACT",
        f"{finding.get('priority')} {finding.get('algorithm')} "
        f"[{finding.get('scanner')}, {finding.get('usage')}]",
        f"Severity {finding.get('severity')}; evidence strength "
        f"{finding.get('evidenceStrength', 'unknown')}; "
        f" Mosca-exposed: {finding.get('mosca_exposed')}.".replace("  ", " "),
        f"Why: {_truncate(finding.get('rationale', ''), 300)}",
        f"Evidence: {_truncate(finding.get('evidence', ''), 160)}",
        f"Recommendation: {_truncate((finding.get('recommendation') or {}).get('recommend', ''), 200)}",
        f"Related findings: {len(related)}"
        + (f" ({len(runtime)} runtime observation(s))" if runtime else ""),
        "",
        "## INTERPRETATION",
        ("This was observed at runtime under controlled execution; treat static "
         "matches as corroborating, not redundant." if finding.get("scanner") == "runtime"
         else "Static evidence alone does not prove runtime use; "
              + ("a controlled runtime observation supports it." if runtime
                 else "no runtime observation covers it in this scan.")),
        "",
        "## UNKNOWN",
        "Whether this is exploitable; whether migration is complete; exact timelines.",
    ])


def explain_migration(report: dict) -> str:
    """Migration roadmap explanation from the actual plan."""
    migration = report.get("migration") or {}
    roadmap = migration.get("roadmap", {})
    items = {item["id"]: item for item in migration.get("workItems", [])}
    lines = ["## FACT"]
    for bucket in ("Immediate", "Near-term", "Planned", "Monitor"):
        ids = roadmap.get(bucket, [])
        lines.append(f"{bucket} ({len(ids)}):")
        for item_id in ids[:5]:
            item = items.get(item_id, {})
            lines.append(f"- {item.get('priority', '?')} {item.get('family', '?')}: "
                         f"{_truncate(item.get('direction', ''), 120)}")
    lines += ["",
              "## INTERPRETATION",
              "Work the Immediate bucket first; each item lists affected artifacts "
              "and unknowns that need human judgment.",
              "",
              "## UNKNOWN",
              "Migration complexity, costs, deadlines, completion status."]
    return "\n".join(lines)


def explain_relationships(report: dict, finding_id: str | None = None) -> str:
    """Relationship explanation from correlation data, not invented links."""
    components = {c["id"]: c for c in report.get("components", [])}
    if finding_id is not None:
        target = components.get(finding_id)
        if target is None:
            raise KeyError(f"unknown finding id: {finding_id}")
        lines = [f"## FACT — relations of {target.get('algorithm')} "
                 f"[{target.get('scanner')}]"]
        for link in target.get("related", [])[:8]:
            other = components.get(link["id"], {})
            lines.append(f"- {link['relation']}: {other.get('algorithm', link['id'])} "
                         f"[{other.get('scanner', '?')}]")
        if target.get("correlation", {}).get("supports"):
            lines.append(f"- runtime supported by "
                         f"{len(target['correlation']['supports'])} static finding(s)")
        if len(lines) == 1:
            lines.append("- no links in this scan (not proof of isolation)")
    else:
        inventory = (report.get("intelligence") or {}).get("inventory", [])
        lines = ["## FACT — cross-scanner families"]
        for row in inventory[:10]:
            lines.append(f"- {row.get('family')}: {', '.join(row.get('scanners', []))} "
                         f"({row.get('findingCount')} findings)")
    return "\n".join(lines + ["",
                              "## INTERPRETATION",
                              "Shared families across scanners suggest one usage chain; "
                              "verify before merging remediation work.",
                              "",
                              "## UNKNOWN",
                              "Whether linked evidence shares one runtime code path."])


def executive(report: dict) -> str:
    """Leadership summary using only report numbers. No invented metrics."""
    summary = report.get("summary", {})
    migration = report.get("migration") or {}
    roadmap = migration.get("roadmap", {})
    immediate = len(roadmap.get("Immediate", []))
    return "\n".join([
        "## FACT",
        f"{summary.get('total', 0)} cryptographic findings across "
        f"{len((report.get('intelligence') or {}).get('inventory', []))} algorithm families; "
        f"{immediate} migration work item(s) need immediate investigation.",
        "",
        "## INTERPRETATION",
        ("Risk concentrates in legacy asymmetric cryptography and weak primitives; "
         "the migration roadmap orders remediation without calendar claims."
         if immediate else
         "No immediate migration items; planned/monitor hygiene still applies."),
        "",
        "## UNKNOWN",
        "Business impact, remediation cost/effort, compliance posture.",
    ])


def route(question: str, report: dict, finding_id: str | None = None) -> tuple[str, str]:
    """Keyword-route a question to a renderer. Returns (kind, answer)."""
    text = (question or "").lower()
    if finding_id is not None or "why is this" in text or "why is it" in text or "p0" in text:
        if finding_id is None:
            top = _top(report, 1)
            finding_id = top[0]["id"] if top else None
        if finding_id is None:
            return "summary", summarize(report)
        return "finding", explain_finding(report, finding_id)
    if "migrat" in text or "first" in text or "roadmap" in text or "fix first" in text:
        return "migration", explain_migration(report)
    if "relat" in text or "connect" in text or "openssl" in text:
        return "relationships", explain_relationships(report, finding_id)
    if "executive" in text or "leadership" in text or "overview" in text:
        return "executive", executive(report)
    return "summary", summarize(report)
