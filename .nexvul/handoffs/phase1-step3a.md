# Handoff: Phase 1, step 3a (findings, rule API, scan pipeline, terminal + JSON reporters, CLI)

| Field | Value |
|-------|-------|
| Author | Implementation engineer (agent) |
| Date | 2026-10-13 |
| Scope | Finding model, rule-plugin API (built-in frozen registry only), end-to-end `scan` pipeline, inline suppressions, terminal and JSON reporters, `scan`/`rules`/`explain`/`doctor` CLI. **No real detection rules** (the shipped registry is empty). |
| Commits | None (not asked to commit) |

## 1. What was built

| Path | Contents |
|------|----------|
| `src/nexvul/findings/model.py` | `Severity`/`Confidence` enums (words, ranked), `FlowRole`, `Finding` (rule id, title, severity, confidence, ordered ASI labels, `FindingLocation` with 1-based line/col + `raw_path_b64` for non-UTF-8 names, message, flow steps with role words, evidence, remediation, references, CWE, limitations, `Suppression` state), `fingerprint()` (sha256 over rule id, normalised path bytes, flow shape and sink context; no line numbers; length-prefixed fields), `disambiguate()` for repeats. `REPORT_SCHEMA_VERSION = "1.0.0"`. |
| `src/nexvul/findings/redact.py` | Secret redaction for snippets (token prefixes, `password = "..."`, `Bearer`), bounded linear patterns, input capped first (SR-24). |
| `src/nexvul/findings/result.py` | `ScanResult` (tool/rule-pack versions, target basename, mode, commit, timestamps, CI reason, fail-on, enabled rules, effective config per key with sources, config changes, config sources with sha256, `CompletenessReport`, active + suppressed findings, suppression issues, languages, analysis-limited notes, exit code, timings). |
| `src/nexvul/rules/base.py` | `RuleMeta` (id, name, ordered ASI list, default severity, confidence ceiling, `Readiness` default/experimental, remediation, references, CWE, `RuleDoc` for explain), `Rule` ABC with `check(RuleContext) -> Iterable[Match]`, `Match`/`FlowStepDraft`/`EvidenceDraft`, `code()` identifier cap. |
| `src/nexvul/rules/registry.py` | Frozen `BUILTIN_RULES = ()` table, immutable `Registry` (dup/type checks, ID index, canonical metadata sha256, selection by rule ID or ASI selector, experimental off unless enabled, enabled wins). No entry points, no dynamic loading. |
| `src/nexvul/rules/engine.py` | Runs rules over parsed IR; rule exceptions and contract violations (non-`Match`, unknown path) recorded as `RuleFailure(rule_id, error_type)` -> partial; matches yielded before a raise are kept; per-file (100) / total (10,000) caps counted -> partial; every repo-derived string sanitised once here. |
| `src/nexvul/rules/suppressions.py` | DEC-0007 OD-04 syntax `# nexvul: ignore[NEX006,NEX010] -- reason`; rejected (warning, finding stays active, all modes): bare ignore / no rule ID, invalid or unknown ID (did-you-mean), non-`ignore` directives (no blanket/file-level), hidden chars (bidi, zero-width, controls; named as `U+202E RIGHT-TO-LEFT OVERRIDE`), non-ASCII in directive (homoglyphs), malformed tail, >20 IDs, over-long comment. Justification optional locally (applies, listed "(no justification)" + warning); in CI required, >= 10 chars, else NOT APPLIED. Unmatched suppressions listed. Suppressed findings kept. |
| `src/nexvul/ir/model.py`, `parser/python.py` | `SuppressionComment(text, truncated, location, target_line)` on `ModuleIR.suppressions`, extracted **in the worker** from `tokenize` COMMENT tokens (trailing -> own line; standalone -> next code line). IR schema 0.1.0 -> **0.2.0** (additive). |
| `src/nexvul/core/scan.py` | Pipeline: root check -> module-origin guard -> repo config + CLI override layer -> discovery -> workers (same ledger) -> rules -> suppressions -> status/exit code. Root `.nexvul.yml` is recorded as `nexvul_config` (info), not as unparsed YAML. Zero analysed files = FAILED, exit 3 (`nothing_to_analyse` / `none_analysed`), never downgraded by `--allow-partial`. |
| `src/nexvul/reporting/terminal.py`, `tokens.py` | T02-T07, T12, T15-T18 layouts at >=120 / 80-119 / 40-79 / <40 (no wrap); plain mode (non-TTY, NO_COLOR, TERM=dumb, --no-color): zero ESC, ASCII meter/rules, compact spacing; SGR only around trusted text; completeness block always printed; result line last with the PARTIAL banner as the final line; T21 status line and C05 stderr warnings. Tokens mirror `docs/design/tokens.json` (test-enforced). |
| `src/nexvul/reporting/json_report.py`, `src/nexvul/schemas/report-1.0.0.json` | J01 key order, required `completeness` (threat-model §7 fields + rule failures, allow_partial), effective config per key with sources, config file sha256, weakening changes applied/not_applied, `untrusted_fields`, position encoding declared (`utf8_bytes`, 1-based). Schema shipped as package data. |
| `src/nexvul/reporting/output.py` | `--output` checks before scanning: refuse inside root unless explicit, `.git/`, symlink destination, symlinked dir inside root (no `--force` path), non-report overwrite (needs `--force`); atomic `O_EXCL|O_NOFOLLOW` temp + `os.replace` via dir fd, temp removed on failure. |
| `src/nexvul/reporting/utility.py`, `cli/main.py` | `scan PATH [--format terminal\|json] [--output FILE] [--fail-on LEVEL] [--ci] [--allow-partial] [--verbose] [--no-color] [--force]`, `rules`, `explain RULE` (ID normalised, U04 did-you-mean), `doctor` (version/path, Python, import-path flags, parsers, real worker probe, enforced limits, memory limit per OS, rule pack hash, plugins, install-inside-cwd and modules-from-cwd warnings, no network), `version` unchanged. T09/T10/T11/T20/T22 error screens. |
| Tests | `tests/unit/test_findings_model.py`, `test_rules_api.py`, `test_rules_engine.py`, `test_suppressions.py`, `test_scan_pipeline.py` (incl. 32-row exit-code precedence table), `test_reporting_terminal.py` (golden files `tests/golden/terminal/*`: 9 scenarios x {80, 120, 60, plain-80} + 3 colour goldens, width checks, copy lint, token sync), `test_reporting_json.py` (in-test JSON-Schema validator over every scenario, golden `tests/golden/json/T17-ci.json`), `test_reporting_output.py`, `test_cli_scan.py`; `tests/security/test_mf_output.py` (hostile filenames: ANSI, OSC 8, OSC 52, newline, bidi, zero-width, C1, markup lookalike; hostile rule messages; hostile suppressions; CI loosening; partial/nothing-to-analyse exit 3; rule exception; output symlink/inside-root refusal). Test-only rules: `tests/support/nexvul_test_rules.py`; synthetic results: `tests/support/result_factory.py` (`tests/support` added to pytest `pythonpath`). |

## 2. Choices

- **No Rich dependency.** Untrusted text is never interpreted as markup because there is no markup layer: the reporter emits SGR only around nexvul's own strings, and every repo string is sanitised (twice: at finding build, then `ensure_display_safe`). Avoids adding a dependency without approval.
- **Findings hold display-safe strings**, sanitised once in the engine (no double escaping); fingerprints use raw values.
- **Rules run in the supervisor** on decoded IR only (no bytes). The analysis worker with budgets/kill comes with taint (architecture §5.2 deviation).
- **CLI flags outrank repo config**: new `overrides` parameter on `resolve_config` applied after the repo layer.
- **Partial banner after the result line** (T05 mock-up and threat model §7 rule 2); the result line is last for complete/failed scans.
- **Doctor `info` (not `warn`) for by-design gaps** (no JS/TS parser, macOS memory limit) so doctor exits 0 on a normal install; warn/fail for fixable problems.
- **Text output via `--output`** is plain (no colour).
- Memory-limit note reworded to DEC-0013 form: `limit not enforced: memory (macOS); file-size and nesting caps apply`.

## 3. Doc conflicts / items for the Supervisor

1. **Bare ignore**: DEC-0004 §2 says "config error in CI"; screen-inventory C05 and the task say "rejected with a warning". Implemented: rejected with warning in every mode, finding stays active, exit code unaffected. Decide whether CI should exit 2.
2. **Justification length**: C03 says 10-300 chars; enforced only as a CI minimum (10). Locally any length; display capped at 120.
3. **Body wrap width at 120 columns**: mock-ups draw ~115-char body lines; design-system §5.6 says `min(width-2, 100)`. Implemented the design-system rule.
4. **Step-2 contract change**: `core/workers._validate_rel_path` rejected backslashes; a hostile POSIX filename containing `\` aborted the whole scan with exit 4. Fixed (backslash allowed; test param removed, regression test added). Please confirm.
5. **New `SkipReason.NEXVUL_CONFIG` (info)**: without it, every repo with a `.nexvul.yml` was PARTIAL (YAML has no parser yet).
6. `--force` added to `scan` (T22 needs it; not in the step brief's flag list). `--fail-on never`, `--quiet`, `--explain`, `--color=always`, `--config-base`, `precommit` not implemented.
7. `nexvul version` left unchanged (U07 wants rule-pack hash + Python; the hash is in `doctor` and every report).
8. Header always prints "Frameworks none recognised (no framework recognisers in this version)"; T19's rule-count note is not produced (no framework-dependent rules exist).
9. Architecture §11.3 build-time rule-pack integrity check (exit 4 on mismatch) not implemented; hash is computed and printed.

## 4. Commands run and outcomes (2026-10-13, macOS arm64, Python 3.13.12 venv)

| Command | Outcome |
|---------|---------|
| `pytest -q --cov=nexvul --cov-branch` | **806 passed, 2 skipped** (MF-25, MF-64 Linux-only, unchanged), ~32 s; TOTAL 98% (coverage.py combined) |
| `ruff check .` | All checks passed |
| `ruff format --check .` | 67 files already formatted |
| `mypy --strict src` | Success: no issues found in 33 source files |

### 4a. Coverage of new modules (coverage.py combined line+branch)

findings/model 100%, redact 100%, result 99%; rules/base 100%, registry 100%, engine 98%,
suppressions 99%; reporting/json_report 100%, output 100%, tokens 100%, terminal 96%, utility 97%;
core/scan 96%; cli/main 97%. Worker-process code stays `pragma: no cover` as in step 2.

## 5. Known gaps

- Widths count code points; East Asian wide characters can overflow a line.
- No OSC 8 links, no T01 progress line, no `--quiet` (T14), no `--explain` inline (T13).
- Path did-you-mean (T10) not implemented.
- Ledger keeps at most 1,000 skipped paths; when many info-level skips fill it, partial-reason paths may show only as "and N more" (counts stay exact).
- Rule failures record only the exception class name; there is no per-rule time budget yet.
- Not run on Linux or Python 3.12 in this step.

## 6. Inputs for step 3b (SARIF + HTML)

- Render from `ScanResult` only; reuse `json_report.finding_to_dict` field semantics. Strings are already display-safe; still pass through `ensure_display_safe`, then format-specific escaping (HTML `html.escape`; SARIF `message.text` only).
- SARIF: `executionSuccessful = (status == complete)`; one `toolExecutionNotifications` per `completeness.skipped_by_reason` partial reason and per `rule_failures`; `toolConfigurationNotifications` from `config_changes`; `columnKind`: our columns are 1-based **UTF-8 byte** offsets (`COLUMN_UNIT`) - convert to `unicodeCodePoints` per line or document the mismatch (SR-29). Suppressed findings -> `suppressions[{kind: "inSource", justification}]`; NOT APPLIED stay unsuppressed. `partialFingerprints` from `Finding.fingerprint`. Rule `help` from `RuleMeta.doc` only.
- HTML: non-dismissable banner for PARTIAL/FAILED, disclaimer `tokens.DISCLAIMER`, no external fetches; output writer `reporting/output.py` already handles path policy (add the `html`/`sarif` markers to `_is_nexvul_file`).

## 7. Inputs for step 4 (first rule NEX007: MCP config without authentication)

- NEX007 targets JSON configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`): a JSON/JSONC **parser in the worker** emitting a config IR is needed first (today JSON is `parser_unavailable` -> partial). Python-side MCP clients can use `ModuleIR.calls` (`callee.resolved`, keyword constants).
- Add the rule class to `BUILTIN_RULES`, give it a `RuleDoc` (U03), ASI labels `("ASI07", "ASI04")` per mapping, fixtures as `tests/rules/NEX007/.../case_nnn_*.json.fixture`. `Match.context` should be the server name + URL so fingerprints are stable. Message formula (design-system §8.2 config finding); never put the URL into anything but `message`/evidence (sanitised by the engine). Bump `RULE_PACK_VERSION`.
