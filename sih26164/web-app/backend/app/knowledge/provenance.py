"""Provenance for the ECDAT security knowledge layer.

Every knowledge entry derives from the external skill repository below. Entries
are ECDAT-authored normalized summaries (not verbatim copies); skill scripts
were never imported or executed. Content is static data, pinned to one commit.
"""

SOURCE_REPOSITORY = "mukul975/Anthropic-Cybersecurity-Skills"
SOURCE_COMMIT = "54a798831d2266a3ca61ce68a7acb80b81160d57"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_INDEX_VERSION = "1.1.0"
IMPORTED_AT = "2026-09-06"
SCHEMA_VERSION = 1

ADVISORY_NOTE = ("Security knowledge is advisory context for observed evidence. "
                 "Deterministic ECDAT findings remain authoritative.")


def source_ref(skill_id: str) -> dict:
    return {"repository": SOURCE_REPOSITORY, "skill": skill_id,
            "commit": SOURCE_COMMIT, "license": SOURCE_LICENSE}
