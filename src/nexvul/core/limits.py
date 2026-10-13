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

# --------------------------------------------------------------------------------------------
# Parse stage (worker isolation and per-file parse limits) - T-02, T-03, SR-03..05, arch §5.2-5.3
# --------------------------------------------------------------------------------------------

#: Maximum bracket + indentation nesting estimated from the token stream before ``ast.parse``.
#: CPython's own tokenizer stops at 200 nested brackets and 100 indent levels; real code is far
#: below either. Architecture §5.3 "max_nesting".
MAX_NESTING: Final = 100

#: Maximum number of AST nodes (every node yielded by an iterative child walk, operators
#: included). Architecture §5.3 "max_ast_nodes".
MAX_AST_NODES: Final = 500_000

#: Maximum characters of one string literal kept in the IR (longer: truncated and flagged).
#: Truncation does not make the scan partial (architecture §5.3 ``literal_truncated``).
MAX_LITERAL_CHARS: Final = 10_000

#: JSON/JSONC data files (step 4). Values beyond these caps: keys are truncated and flagged;
#: a document with more values than ``MAX_CONFIG_ENTRIES`` is not analysed (``max_ast_nodes``),
#: and a number literal longer than ``MAX_JSON_NUMBER_CHARS`` is rejected (``parse_error``).
MAX_CONFIG_KEY_CHARS: Final = 1_000
MAX_CONFIG_ENTRIES: Final = 100_000
MAX_JSON_NUMBER_CHARS: Final = 100
MAX_CONFIG_POINTER_CHARS: Final = 512
MAX_DUPLICATE_KEYS_LISTED: Final = 100

#: Maximum characters of a rendered expression summary or dotted name kept in the IR.
MAX_EXPR_TEXT_CHARS: Final = 200

#: Maximum AST depth rendered into one expression summary (deeper parts become ``...``).
MAX_EXPR_RENDER_DEPTH: Final = 6

#: Maximum AST nodes visited while summarising one expression (bounds quadratic blow-up on
#: nested calls such as ``f(g(h(...)))``).
MAX_EXPR_VISIT_NODES: Final = 256

#: Maximum names recorded as referenced by one expression summary.
MAX_EXPR_NAMES: Final = 32

#: Maximum attribute-chain length resolved into a dotted name (longer chains are ``dynamic``).
MAX_ATTRIBUTE_CHAIN: Final = 32

#: Default per-file wall-clock limit for read + decode + parse + IR, enforced by the supervisor
#: with a hard kill of the worker process (architecture §5.1-5.2).
DEFAULT_PARSE_TIMEOUT_SECONDS: Final = 10.0

#: Absolute ceiling for the per-file parse timeout from any source.
HARD_MAX_PARSE_TIMEOUT_SECONDS: Final = 120.0

#: Default ceiling on the number of parse workers (architecture §5.2: ``min(cpu_count, 8)``).
DEFAULT_MAX_WORKERS: Final = 8

#: Worker address-space limit (``RLIMIT_AS``), applied on Linux only; macOS does not enforce it
#: reliably (open risk R-3). Also the RSS cap the supervisor polls on Linux.
WORKER_MEMORY_LIMIT_BYTES: Final = 1 * GIB

#: Soft file-descriptor limit inside a worker (it needs stdio, one pipe, and a short fd chain).
WORKER_MAX_OPEN_FILES: Final = 64

#: Extra CPU seconds above the wall-clock limit for the ``RLIMIT_CPU`` backstop.
WORKER_CPU_MARGIN_SECONDS: Final = 2

#: Maximum size of one JSON message a worker may send to the supervisor. Larger => the worker is
#: killed and the file recorded as ``parser_crashed`` (protocol violation).
MAX_WORKER_RESULT_BYTES: Final = 64 * MIB

#: Number of worker deaths a single file may cause before it is not retried (architecture §5.2:
#: "a file that kills two workers is not retried a third time").
MAX_CRASH_ATTEMPTS_PER_FILE: Final = 2

#: Maximum characters of a resolved dotted name. A longer name (only possible with absurd
#: identifiers) is recorded as ``dynamic`` rather than truncated, so it can never match a spec.
MAX_DOTTED_NAME_CHARS: Final = 1024


# ---------------------------------------------------------------------------------------------
# Suppressions, findings and reports (Phase 1 step 3a)
# ---------------------------------------------------------------------------------------------

#: Characters of one suppression comment kept in the IR (longer comments are flagged truncated).
MAX_SUPPRESSION_COMMENT_CHARS: Final = 1_000

#: Suppression comments recorded per file; more are counted in a module note, not recorded.
MAX_SUPPRESSION_COMMENTS_PER_FILE: Final = 1_000

#: Rule IDs accepted in one ``ignore[...]`` list.
MAX_SUPPRESSION_RULE_IDS: Final = 20

#: Minimum justification length required in CI mode (screen-inventory C03: 10-300 characters).
MIN_CI_JUSTIFICATION_CHARS: Final = 10

#: Finding caps (architecture §15). Hitting either is recorded and makes the scan partial.
MAX_FINDINGS_PER_FILE: Final = 100
MAX_FINDINGS_TOTAL: Final = 10_000

#: Display caps for finding text (tokens.json -> truncation).
MAX_MESSAGE_CHARS: Final = 400
MAX_IDENTIFIER_CHARS: Final = 80
MAX_JUSTIFICATION_DISPLAY_CHARS: Final = 120
MAX_SNIPPET_CHARS: Final = 200
MAX_FLOW_STEPS: Final = 50
MAX_EVIDENCE_ITEMS: Final = 20

#: Analysis-limited notes kept for ``--verbose`` / JSON (the count is always exact).
MAX_LIMITED_NOTES: Final = 200
