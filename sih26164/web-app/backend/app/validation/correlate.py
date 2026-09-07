"""Link validation observations to static findings. Presentation only.

Never changes severity, priority, Mosca, recommendations, or counts.
A finding gains `validationStatus` + `correlatedValidations`; nothing else.
"""

from __future__ import annotations

from ..risk import base_algorithm, canon


def _family(algorithm: str) -> str:
    try:
        return canon(algorithm or "")
    except Exception:
        return base_algorithm(algorithm or "")


def correlate_finding(finding: dict, results: list[dict]) -> tuple[str, list[str]]:
    """Roll up one finding's validation results -> (status, validation_ids)."""
    linked = [r for r in results if r.get("finding_id") == finding.get("id")]
    if not linked:
        # Family-level runtime observation without an explicit link.
        fam = _family(str(finding.get("algorithm") or ""))
        observed = [r for r in results
                    if r.get("validation_type") == "runtime"
                    and r.get("status") in ("OBSERVED", "CONFIRMED")
                    and _family(str(r.get("observed_algorithm") or "")) == fam]
        if observed:
            return "RUNTIME_OBSERVED", [r["validation_id"] for r in observed[:5]]
        return ("NOT_APPLICABLE"
                if (finding.get("is_mock") or finding.get("usage") == "dependency integrity metadata")
                else "STATIC_ONLY"), []
    statuses = {r.get("status") for r in linked}
    ids = [r["validation_id"] for r in linked[:8]]
    if "CONFIRMED" in statuses:
        return "RUNTIME_CONFIRMED", ids
    if "PARTIALLY_CONFIRMED" in statuses:
        return "RUNTIME_CORRELATED", ids
    if "OBSERVED" in statuses:
        return "RUNTIME_OBSERVED", ids
    if "NOT_APPLICABLE" in statuses and len(statuses) == 1:
        return "NOT_APPLICABLE", ids
    return "STATIC_ONLY", ids


def apply_correlation(components: list[dict], results: list[dict]) -> None:
    """Stamp validationStatus onto findings in place (additive metadata only)."""
    for row in components:
        status, ids = correlate_finding(row, results)
        row["validationStatus"] = status
        row["correlatedValidations"] = ids
    # Runtime observations with no static link stay visible, honestly labeled.
    linked_ids = {vid for row in components for vid in row.get("correlatedValidations", [])}
    for result in results:
        if (result.get("validation_type") == "runtime"
                and result.get("validation_id") not in linked_ids
                and not result.get("finding_id")):
            result["correlation_status"] = "UNRELATED_RUNTIME_OBSERVATION"
