"""CBOM builder: standardized JSON report. MOCK findings always badged."""

from __future__ import annotations

from datetime import datetime, timezone

TOOL = "ecdat"
VERSION = "0.2.0"


def build_cbom(target: str, enriched: list[dict], context_provenance: dict | None = None,
               scanner_sources: list[str] | None = None) -> dict:
    mocks = sum(1 for f in enriched if f.get("is_mock"))
    by_sev: dict[str, int] = {}
    for f in enriched:
        by_sev[f.get("severity", "low")] = by_sev.get(f.get("severity", "low"), 0) + 1
    algorithms = sorted({f["algorithm"] for f in enriched})
    scanners = sorted(scanner_sources) if scanner_sources is not None else sorted(
        {f["scanner"] for f in enriched})
    recommendations = []
    for finding in enriched:
        recommendation = finding.get("recommendation", {}).get("recommend")
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
    exposed = sum(1 for f in enriched if f.get("mosca_exposed"))
    priorities = {level: sum(1 for f in enriched if f.get("priority") == level)
                  for level in ("P0", "P1", "P2", "P3")}
    return {
        "bomFormat": "ECDAT-CBOM",
        "specVersion": "0.2",
        "reportType": "CBOM-style / CBOM-oriented (not independently standards-verified)",
        "tool": {"name": TOOL, "version": VERSION},
        "target": target,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "summary": {"total": len(enriched), "mock": mocks, "real": len(enriched) - mocks,
                    "bySeverity": by_sev},
        "metadata": {"scanTarget": target, "findingCount": len(enriched),
                     "scannerSources": scanners, "algorithmInventory": algorithms,
                     "contextProvenance": context_provenance or {"available": False}},
        "riskSummary": {"moscaExposed": exposed, "priorities": priorities,
                        "note": "Priorities are deterministic migration ordering, not QRQC prediction."},
        "recommendations": recommendations,
        "mockWarning": ("CONTAINS MOCK FINDINGS — illustrative only, not discovery"
                        if mocks else None),
        "components": enriched,
    }
