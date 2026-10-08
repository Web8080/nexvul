"""Named, documented self-protection limits (SR-04, threat model T-02, T-04, T-05, T-22).

Every limit here exists because the scanned repository is hostile. Hitting any limit that stops
nexvul from looking at in-scope content makes the scan **partial** (DEC-0004 §3); it is never
silently treated as "nothing there".

Which limits may be changed, and by whom, is decided in ``nexvul.core.config`` (architecture §3,
§5.3). Constants prefixed ``HARD_`` are absolute ceilings that no configuration source can exceed.
"""

from __future__ import annotations

from typing import Final

KIB: Final = 1024
MIB: Final = 1024 * KIB
GIB: Final = 1024 * MIB

# --------------------------------------------------------------------------------------------
# Configuration file (.nexvul.yml) - T-04, SR-28, architecture §3.2
# --------------------------------------------------------------------------------------------

#: Maximum size of any config file, checked with fstat before a single byte is parsed.
MAX_CONFIG_BYTES: Final = 64 * KIB

#: Maximum nesting depth of YAML collections. The schema needs depth 2; 8 leaves room for
#: helpful error messages without allowing recursion bombs.
MAX_CONFIG_DEPTH: Final = 8

#: Maximum number of YAML parser events. Bounds work on pathological but small documents.
MAX_CONFIG_EVENTS: Final = 20_000

#: Maximum number of items in any list-valued config key (rules.enabled, exclude, ...).
MAX_CONFIG_LIST_ITEMS: Final = 512

#: Maximum length of any string value in config (patterns, rule ids, severities).
MAX_CONFIG_STRING_CHARS: Final = 512

# --------------------------------------------------------------------------------------------
# Per-file limits - T-02, SR-04, architecture §5.3
# --------------------------------------------------------------------------------------------

#: Default maximum size of a file nexvul will analyse (checked via lstat before open).
DEFAULT_MAX_FILE_SIZE: Final = 1 * MIB

#: Absolute ceiling for max_file_size from any source.
HARD_MAX_FILE_SIZE: Final = 16 * MIB

#: Number of leading bytes sniffed for binary content (NUL byte => binary). Architecture §5.3.
BINARY_SNIFF_BYTES: Final = 8 * KIB

# --------------------------------------------------------------------------------------------
# Global discovery limits - T-05, T-22, SR-04, architecture §4.3
# --------------------------------------------------------------------------------------------

#: Default maximum number of in-scope files selected for analysis (brief §14 analysis.max_files).
DEFAULT_MAX_FILES: Final = 50_000

#: Absolute ceiling for max_files from any source (repo config may raise up to this, never above).
HARD_MAX_FILES: Final = 200_000

#: Maximum directory depth below the scan root that discovery descends to.
MAX_DIR_DEPTH: Final = 64

#: Maximum number of directory entries (files, dirs, links, specials) discovery will look at.
#: Bounds file-count bombs made of files that are not even candidates (MF-20).
MAX_DIR_ENTRIES: Final = 1_000_000

#: Maximum total bytes of selected files. Further files are not selected and the scan is partial.
MAX_TOTAL_BYTES: Final = 2 * GIB

#: Wall-clock budget for discovery as a whole, in seconds.
DISCOVERY_TIME_BUDGET_SECONDS: Final = 120.0

# --------------------------------------------------------------------------------------------
# Git metadata (bounded read-only carve-out, SR-06, architecture §4.2, R-6)
# --------------------------------------------------------------------------------------------

#: Maximum size of .git/index that will be read. Large monorepos are ~10-100 MiB; above this the
#: index is treated as unreadable (directory-mode fallback, partial).
MAX_GIT_INDEX_BYTES: Final = 128 * MIB

#: Maximum number of entries declared in the index header.
MAX_GIT_INDEX_ENTRIES: Final = 1_000_000

#: Maximum length in bytes of one path stored in the index.
MAX_GIT_PATH_BYTES: Final = 4 * KIB

#: Maximum size of .git/HEAD and of a ``.git`` gitdir pointer file.
MAX_GIT_SMALL_FILE_BYTES: Final = 1 * KIB

# --------------------------------------------------------------------------------------------
# Reporting of untrusted strings - T-10, T-22, SR-10
# --------------------------------------------------------------------------------------------

#: Maximum characters of a sanitised path shown for display (longer: truncated + hash suffix).
MAX_DISPLAY_PATH_CHARS: Final = 240

#: Maximum number of individual skipped paths kept in the completeness ledger. Counts by reason
#: stay exact; only the illustrative path list is capped (threat model §7 rule 7).
MAX_SKIPPED_PATHS_LISTED: Final = 1_000
