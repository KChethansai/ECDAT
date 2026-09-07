"""Source acquisition boundary: local dirs and remote repos become normalized workspaces.

The ONLY network introduced here is GitHub acquisition (allowlisted hosts,
bounded, validated redirects). Analysis downstream is unchanged and offline.
"""

from .acquire import (AcquisitionError, AcquisitionPolicy, candidate_archives,
                      extract_archive, fetch_bytes, isolated_workspace, resolve_ref,
                      topdir_sha)
from .github_url import parse_github_url
from .history import apply_triage, delta, history_record, set_triage
from .normalize import logical_prefix, relativize_report, stamp_fps
from .profiles import PROFILES, resolve_profile

__all__ = ["AcquisitionError", "AcquisitionPolicy", "PROFILES", "apply_triage",
           "candidate_archives", "delta", "extract_archive", "fetch_bytes",
           "history_record", "isolated_workspace", "logical_prefix",
           "parse_github_url", "relativize_report", "resolve_profile",
           "resolve_ref", "set_triage", "stamp_fps", "topdir_sha"]
