"""Scan profiles: named capability selections over the existing pipeline."""

from __future__ import annotations

PROFILES = {
    # profile: (crypto scanners or "ALL", code categories or "ALL"/None, validate default)
    "quick": (["source", "dependency", "binary"], ["dead_code", "dependencies", "structure"], False),
    "crypto": ("ALL", None, False),
    "codebase": (["source"], "ALL", False),
    "full": ("ALL", "ALL", False),
    "full-validation": ("ALL", "ALL", True),
}


def resolve_profile(name: object, explicit_scanners: list[str] | None,
                    explicit_code: bool, explicit_validate: bool) -> dict:
    """Map profile + explicit flags to pipeline inputs. Explicit flags win when set."""
    profile = name or "full"
    if profile not in PROFILES:
        raise ValueError(f"unknown profile '{profile}' (valid: {sorted(PROFILES)})")
    scanners, code_cats, validate = PROFILES[profile]
    if explicit_scanners:
        scanners = explicit_scanners  # explicit scanner list overrides the profile
    return {"profile": profile,
            "scanners": None if scanners == "ALL" else list(scanners),
            "code_analysis": explicit_code or code_cats is not None,
            "code_categories": None if code_cats == "ALL" else (
                list(code_cats) if code_cats else None),
            "validate": explicit_validate or validate}
