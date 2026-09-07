"""Knowledge registry: assembly + structural validation.

32 skills (16 cryptography Tier-1, 16 adjacent Tier-2). Static data only —
no skill scripts are imported or executed anywhere in ECDAT.
"""

from __future__ import annotations

from . import _adjacent, _crypto
from .provenance import source_ref

REQUIRED_FIELDS = ("id", "source_skill", "name", "domain", "tier", "summary",
                   "guidance", "verification", "considerations", "applies",
                   "frameworks")
APPLIES_FIELDS = ("algorithms", "scanners", "categories", "usages")
DOMAINS = ("cryptography", "supply-chain", "cloud", "container", "devsecops")


def _attach_provenance(entry: dict) -> dict:
    record = dict(entry)
    record["provenance"] = source_ref(entry["source_skill"])
    return record


SKILLS: list[dict] = [_attach_provenance(e)
                      for e in (_crypto.CRYPTO_SKILLS + _adjacent.ADJACENT_SKILLS)]

BY_ID: dict[str, dict] = {s["id"]: s for s in SKILLS}


def validate() -> list[str]:
    """Structural problems; empty means the registry is well-formed."""
    problems: list[str] = []
    seen: set[str] = set()
    for entry in SKILLS:
        for field in REQUIRED_FIELDS:
            if field not in entry:
                problems.append(f"{entry.get('id', '?')}: missing {field}")
        if entry["id"] in seen:
            problems.append(f"{entry['id']}: duplicate id")
        seen.add(entry["id"])
        if entry.get("domain") not in DOMAINS:
            problems.append(f"{entry['id']}: unknown domain")
        if entry.get("tier") not in (1, 2):
            problems.append(f"{entry['id']}: bad tier")
        applies = entry.get("applies", {})
        for field in APPLIES_FIELDS:
            if field not in applies or not isinstance(applies[field], list):
                problems.append(f"{entry['id']}: bad applies.{field}")
        if not entry.get("guidance"):
            problems.append(f"{entry['id']}: empty guidance")
        prov = entry.get("provenance", {})
        if not (prov.get("repository") and prov.get("commit")
                and prov.get("license") and prov.get("skill")):
            problems.append(f"{entry['id']}: incomplete provenance")
    return problems
