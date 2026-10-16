# Handoff: Phase 2, step 5a (SARIF 2.1.0 reporter + `--format sarif`)

| Field | Value |
|-------|-------|
| Author | Implementation engineer (agent) |
| Date | 2026-10-16 |
| Scope | Step 5 split by the coordinator: **SARIF half only** (deliverables 1, 2 and the `--format sarif` CLI wiring). HTML reporter is step 5b, not started. |
| Commits | None (not asked to commit) |

## 1. What was built

| Path | Contents |
|------|----------|
| `src/nexvul/reporting/sarif.py` | `render_sarif(result, registry, *, pretty, limits)`, `sarif_log(...)`, `is_nexvul_sarif(head)`. Mapping per github-and-action.md §2-§4 (details §2 below). |
| `src/nexvul/cli/main.py` | `--format terminal\|json\|sarif`. The registry instance used for the scan is the one passed to the SARIF writer. `--output` rules unchanged (path checks before scanning, atomic write); status line says `(SARIF, N findings)`. Exit codes unchanged. |
| `src/nexvul/reporting/output.py` | `_is_nexvul_file` recognises a nexvul SARIF log (overwrite without `--force` only for our own SARIF; a JSON report or foreign file is refused, exit 2). |
| `tests/schemas/sarif-schema-2.1.0.json` + `README.md` | Official OASIS schema, vendored unmodified. Source `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/sarif-2.1/schema/sarif-schema-2.1.0.json` (latest commit touching the file, 2024-05-02); SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` (the `main` copy had the same hash, fetched 2026-10-16). Test-only; not shipped in the wheel. |
| `tests/support/schema_draft04.py` | Dependency-free draft-04 validator covering every keyword the SARIF schema uses (`$ref`, type, enum, pattern, format uri/uri-reference/date-time, min/max, minItems, uniqueItems, items, properties, required, additionalProperties, anyOf, oneOf). Unknown keywords raise, so it cannot silently pass. |
| `tests/unit/test_reporting_sarif.py` | 51 tests: schema hash pin; validator self-test; every synthetic scenario x pretty/compact validated against the official schema; GitHub expectations (required fields, all built-in rules incl. experimental with `enabled:false`, security-severity, tags <= 20, helpUri, ruleIndex consistency, message <= 400 chars, no `message.markdown`, fingerprint format); URIs (`%SRCROOT%`, no scheme/leading `/`/`..`/backslash) and region validity; effective-vs-default severity; code flows; info not uploaded; rule overrides; suppressed vs NOT APPLIED; complete/partial/failed/rule-failure/limit/truncated/counted-skip notifications; config notifications; result-count and gzip-size truncation incl. an unmeetable limit; flow cap; hostile-input test; URI encoding; Markdown escaping and link allowlist; fingerprint stable across a real line move; determinism; overwrite marker; goldens; CLI stdout, `--output`, `--force`, partial exit 3. |
| `tests/golden/sarif/{NEX007-scan,T04,T05,T17-ci}.sarif` | `NEX007-scan` is a real scan (two servers: cleartext high + https-no-auth medium) through `rule_fixtures.scan_virtual`, normalised timestamps/versions. Regenerate with `NEXVUL_UPDATE_GOLDEN=1`. |

## 2. Mapping choices

- **Rules**: every rule in the registry. `defaultConfiguration.enabled = readiness is default`, `level` from default severity; `properties.security-severity` (9.5/8.0/5.5/3.0; none for info), `precision` = confidence ceiling, `tags` = `security`, `external/owasp/asiNN`, `external/cwe/cwe-NNN`, `experimental`. Run state: `invocations[0].ruleConfigurationOverrides` lists rules whose enabled state differs from the default (e.g. NEX007 enabled by `.nexvul.yml`). Findings of a rule not in the registry (test registries) get a minimal trusted fallback descriptor.
- **Help**: written from `RuleMeta`/`RuleDoc` only, §4 section order; `help.markdown` backslash-escapes CommonMark punctuation in the trusted text, examples in fences longer than any backtick run, links only to allowlisted hosts (github.com, modelcontextprotocol.io, owasp.org, genai.owasp.org, cwe.mitre.org); `docs/rules/NEXnnn.md` becomes the fixed docs URL.
- **Message** (`message.text` only): `SEVERITY · sentence. Confidence: x.` plus `Steps: n (Show paths).` and `Suppression NOT APPLIED.` when relevant. The effective severity always leads; ` (rule default HIGH)` is added when it differs (OD-07). URL literals (`scheme://...`, `www.`) are replaced by `<url literal, N chars>` (GitHub auto-links plain-text URLs, §2.1); the unaltered sanitised message is kept in `properties.nexvul.message`. Capped at 400 chars.
- **Fingerprints**: `primaryLocationLineHash` = first 16 hex of `Finding.fingerprint` + `:1` (line-independent, already disambiguated per occurrence), plus `nexvulFingerprint/v1` = full fingerprint.
- **Suppressions**: suppressed -> `suppressions[{kind: inSource, status: accepted, justification, location}]`; NOT APPLIED -> unsuppressed result, message + `properties.nexvul.suppression`.
- **Completeness**: `executionSuccessful` true only when complete and nothing truncated; `exitCode` = scan exit code. Notifications: partial banner (or SCAN FAILED cause) first, one per partial skip reason with up to 10 example file locations, counted (policy) reasons as `note`, info reasons omitted, skipped-list truncation, limits hit, rule failures (with `associatedRule` when the rule has a descriptor), engine finding truncation. `toolConfigurationNotifications` from config changes (applied = warning, NOT APPLIED = note). `runs[0].properties.nexvul` carries the JSON report's completeness, scan, tool, config and summary blocks, frameworks, rules enabled, suppression issues, position encoding, SARIF stats, disclaimer, untrusted fields.
- **Limits**: results sorted severity-first (active before suppressed); max 25,000 results and 10 MB gzip (binary search on the kept prefix); dropping records an `error` notification `nexvul.sarif.truncated` first in the list, sets `executionSuccessful=false`, and fills `properties.nexvul.sarif.results_dropped`. Flows capped at 1,000 steps with a message. Info findings not uploaded (counted).
- `automationDetails.id = "nexvul/"`; `originalUriBaseIds.%SRCROOT%` has a description only (no absolute path, SR-24); no `workingDirectory` for the same reason.

## 3. Conflicts / items for the Supervisor

1. **Columns (SR-29)**: findings carry 1-based UTF-8 byte columns; SARIF has no byte column kind and the reporter has no source text to convert. The run declares `columnKind: utf16CodeUnits` and `properties.nexvul.position_encoding` says the columns are exact only when the line prefix is ASCII. A correct fix needs code-point/UTF-16 columns computed in the worker (parser has the line text). Needs a decision.
2. **Docs URLs (OD-11 open)**: `helpUri`/`informationUri` use `https://github.com/%3Cowner%3E/nexvul/...` (percent-encoded placeholder: a valid URI that cannot name a real account), consistent with `cli._BUG_URL`. Change one constant (`REPO_URL`) when OD-11 is decided.
3. **SARIF truncation does not change the exit code**: the exit code is computed by the scan; the reporter only records truncation (notification, `executionSuccessful=false`, properties). With the engine's 10,000-finding cap, the 25,000-result limit cannot be reached today.
4. **Brief vs design on message lead**: brief says effective severity first "when it differs"; design §2.1 always leads with severity. Implemented: always lead, plus the rule default when it differs (satisfies both).
5. `help.text`/`fullDescription` use `RuleDoc.looks_for` (first paragraph) as summary; there is no separate summary field in `RuleDoc`.
6. Rejected suppressions are only in `properties.nexvul.suppression_issues`, not as notifications.

## 4. Commands run and outcomes (2026-10-16, macOS arm64, Python 3.13.12 venv)

| Command | Outcome |
|---------|---------|
| `pytest -q --cov=nexvul --cov-branch` | **1079 passed, 2 skipped** (MF-25, MF-64 Linux-only, unchanged), 37.6 s; TOTAL 98% |
| `ruff check .` | All checks passed! |
| `ruff format --check .` | 85 files already formatted |
| `mypy --strict src` | Success: no issues found in 43 source files |
| `pytest -q tests/unit/test_reporting_sarif.py` | 51 passed |

Coverage `reporting/sarif.py`: 337 statements, 1 missed; 116 branches, 7 partial (98% combined). `output.py` 100%, `cli/main.py` 97%.

Not run: Linux, Python 3.12, an actual upload to GitHub code scanning (CA-3: how GitHub renders `suppressions`, notifications, `precision`, and URL auto-linking is still unverified), the `.sarif` output with a real repository.

## 5. Gaps

- Column kind mismatch for non-ASCII lines (§3.1).
- No `region.snippet` for config findings (NEX007 has no flow; only the sink step of a flow supplies a snippet).
- No gzip output mode (upload-sarif accepts plain JSON).
- No `versionControlProvenance` (commit is display text in `properties.nexvul.scan.commit`; the Action knows the real SHA).

## 6. Inputs for step 5b (HTML reporter)

- Reuse `json_report.report_dict` blocks as SARIF does; reuse `sarif.defang_urls` only if the HTML needs it (HTML must not link scanned URLs at all).
- CLI: add `html` to the `--format` choice and an `is_nexvul_html` marker in `output._is_nexvul_file`.

## 7. Inputs for step 6 (GitHub Action)

- Run `nexvul scan --ci --format sarif --output "$RUNNER_TEMP/nexvul.sarif" <path>` (output outside the checkout), keep the exit code, then `github/codeql-action/upload-sarif` with `category: nexvul` in a separate step; `automationDetails.id` is `nexvul/`.
- Job summary: status and counts can be read from `runs[0].properties.nexvul.summary` / `.completeness` / `.status` (trusted numbers and enums) and `invocations[0].toolExecutionNotifications` (texts are nexvul templates; inserted paths are sanitised but must still go in code spans per §5.4).
- `results_dropped > 0` in `properties.nexvul.sarif` must be surfaced in the summary.
- NEX007 is experimental: the README must say to enable it in `.nexvul.yml`; in SARIF its `defaultConfiguration.enabled` is false and the run override shows `enabled: true`.
