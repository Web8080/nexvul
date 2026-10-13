# Handoff: Phase 2, step 4 (JSON config parser, MCP config recogniser, first rule NEX007)

| Field | Value |
|-------|-------|
| Author | Implementation engineer (agent) |
| Date | 2026-10-13 |
| Scope | JSON/JSONC parsing in workers into a config IR; MCP client-config recogniser; NEX007 (experimental); fixture harness; benchmark cases + harness v0; docs |
| Commits | None (not asked to commit) |

## 1. What was built

| Path | Contents |
|------|----------|
| `src/nexvul/ir/model.py` | `ConfigValueKind`, `ConfigEntry` (flat: parent index, key or array item, kind, capped value, size, truncated, location), `ConfigDocument` (syntax json/jsonc, entries, duplicate-key pointers). `ModuleIR.config` (additive). IR schema **0.2.0 -> 0.3.0**. |
| `src/nexvul/ir/config_view.py` | `ConfigTree` (children index, last-wins `members`, `occurrences`, `duplicated_keys`, `items`, `string`) and RFC 6901 `pointer_of` (capped). Ignores non-backward parent indices. Iterative. |
| `src/nexvul/parser/json_config.py` | Runs in the worker. Bounded iterative tokenizer (linear-time possessive regexes) + stdlib `json` re-parse as authoritative syntax check. Caps: nesting 100 (before any recursion), 100,000 values, numbers > 100 chars rejected, strings 10,000 chars, keys 1,000 chars. Rejects NaN/Infinity, NUL (binary), UTF-16/32 BOM, invalid UTF-8. Accepts UTF-8 BOM and JSONC (comments, trailing commas), noted. Duplicate keys kept and recorded. Line + UTF-8 byte column per value (incremental, linear). Never raises. |
| `src/nexvul/core/workers.py` | Task carries `language`; `.json` -> `parse_json_config`; reply language must match the task (else protocol violation). YAML/TOML/JS/TS stay `parser_unavailable`. Ledger notes for duplicate keys and JSONC files. |
| `src/nexvul/core/scan.py`, `reporting/terminal.py`, `reporting/utility.py` | `ScanResult.frameworks` = `MCP client config (N files)`; header fallback text `none recognised (MCP client configs only in this version)`; tool parsers list + doctor line for JSON; note when an MCP config is found but NEX007 is not enabled. Language label `JSON`. |
| `src/nexvul/frameworks/mcp/{config,endpoints,python_client}.py` | Recogniser by file name **and** structure; endpoint classification (loopback/unspecified/private/remote/unknown; WHATWG IPv4 spellings, IPv6, trailing dot, percent-encoding, templates); redacted display URL; Python SDK constant-URL client calls. |
| `src/nexvul/rules/asi07/nex007.py`, `rules/registry.py` | NEX007 registered; `RULE_PACK_VERSION` 0.0.0 -> **0.1.0**; readiness **experimental**. |
| `src/nexvul/rules/base.py`, `reporting/utility.py` | `RuleDoc.status_note` and `suppression_note` (shown by `explain`). |
| `tests/support/rule_fixtures.py`, `tests/component/rule_engine/test_rule_fixtures.py` | Fixture harness: `dot-x` path components + `.fixture` suffix -> virtual path; `expect.txt` annotations; all cases of a rule scanned in one temp tree outside the repo through the real pipeline. |
| `tests/rules/nex007/` | 42 cases: positive 11, negative 11, edge_cases 7, adversarial 13 (3 known misses). |
| `tests/unit/test_nex007.py`, `test_parser_json.py`, `test_benchmark_harness.py`; `tests/test_meta.py` | Unit/edge/golden tests; meta-test: no real agent config filename (`.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `settings.json`, ...) or tool dir (`.cursor`, `.vscode`, `.claude`, ...) under `tests/` or `benchmarks/`. Goldens: `tests/golden/terminal/NEX007-finding-100.txt`, `tests/golden/json/NEX007-finding.json`. |
| `benchmarks/{vulnerable,safe,adversarial}/NEX007/BM-NEX007-*/` | 15 cases (6/7/2) with `case.yaml` + `files/**.fixture`. |
| `benchmarks/run.py` | Stdlib-only harness (imports nexvul for the scan): schema validation (built-in subset validator), one scan, §8.1 matching, per-rule TP/FP/FN, FP/FN case lists, label mismatches; ratios + Wilson only at >= 20 labelled cases (DEC-0002). |
| `docs/rules/NEX007.md` | Nine §17 questions, examples, measured counts, JSON parsing limits. `docs/owasp/mapping.md` and `docs/detection-taxonomy.md` NEX007 status -> implemented, experimental. |

## 2. Choices

- **NEX007 ships experimental (off by default).** DEC-0002: < 20 labelled cases -> only `confidence: low` or
  `experimental`. `nexvul rules` shows `experimental`; `explain` prints the status note. Benchmark and fixtures
  enable it via `.nexvul.yml`.
- **Severity/confidence deviates from the taxonomy's single "high/high"**: cleartext = high/high; https with no
  auth = medium/medium (OAuth may be negotiated at connect time; taxonomy §3.2 control-absence = medium);
  private-network hosts one severity step lower (research M8). Confidence capped at medium for structure-only
  files, Claude Desktop, duplicate keys/server names. Taxonomy + mapping rows updated to say this.
- **Duplicate keys**: evaluated last-wins (`JSON.parse`); an overridden duplicate server entry is still evaluated;
  both cases lower confidence to medium and add evidence.
- **JSONC accepted for all `.json`** (noted); a comment does not hide a finding in a strict-JSON client file.
- **Auth indicators are lenient** (any auth-looking key/header counts) to favour precision; header values are never
  copied (names only), URL user-info/query never displayed.
- **`0.0.0.0` / `::` as client destination = not reported** (reaches local machine). Server-side `0.0.0.0` bind
  (taxonomy sink) is not implemented.
- **No YAML parser added.** `.yaml/.yml/.toml` stay `parser_unavailable` (partial). PyYAML is already a
  dependency (used by `core/config.py`), but YAML compose/MCP YAML shapes were out of time scope; nothing new added.
- **`case.yaml` written as JSON** (valid YAML 1.2) so the harness reads it with the stdlib; leading `#` lines are
  stripped before `json.loads`.
- **Fixture paths**: `dot-cursor/mcp.json.fixture` instead of real `.cursor/mcp.json` so no editor/agent loads
  committed hostile configs; `expect.txt` sidecars because JSON has no comments.
- **Python side**: only import-resolved `streamablehttp_client`, `streamable_http_client`, `sse_client` with a
  constant URL. `MultiServerMCPClient`, `mcp.Client` (2.x), TS clients left out (documented).
- **JSON findings cannot be suppressed inline**; documented (`exclude` / `rules.disabled`), shown by `explain`.

## 3. Conflicts / items for the Supervisor

1. Test-path naming: brief says `tests/rules/nex007/`; architecture §11.6 example uses `tests/rules/NEX002/`.
   Used lower-case `nex007` as the brief asked; harness upper-cases the rule ID.
2. Tests whose premise changed (not weakened): `test_mf_output.py` hostile tree and `test_scan_pipeline.py`
   partial test used `.json` as "in scope, no parser"; switched to `.ts` (same intent). Empty-registry tests now
   use `Registry(())`; new tests cover the shipped registry. 39 terminal goldens regenerated: only the
   Frameworks fallback line changed (diff checked).
3. `tests/test_meta.py` forbade any `.py` under `benchmarks/`; the brief requires `benchmarks/run.py`. Added an
   exact-path allowlist `HARNESS_FILES = {"benchmarks/run.py"}`.
4. Benchmark metadata `license.spdx` set to `CC0-1.0` for synthetic cases because the schema requires an enum value
   and the project licence is undecided (pyproject TODO). **Needs a decision.**
5. `labels.labelled_by` set to `["pending: 17-false-positive-hunter", "pending: 02-security-research"]`: the
   schema requires two labellers; no independent labelling has happened. Labels are author-proposed.
6. Taxonomy lists "MCP HTTP servers bound to 0.0.0.0 with no auth" as a NEX007 sink - not implemented here.
7. `harness` uses a subset JSON-Schema validator (keywords present in example.schema.json; `format` ignored).

## 4. Commands run and outcomes (2026-10-13, macOS arm64, Python 3.13 venv)

| Command | Outcome |
|---------|---------|
| `pytest -q --cov=nexvul --cov-branch` | **1028 passed, 2 skipped** (MF-25, MF-64 Linux-only, unchanged), ~34 s; TOTAL 98% |
| `ruff check .` | All checks passed! (also `ruff check benchmarks/run.py`: All checks passed!) |
| `ruff format --check .` | 81 files already formatted |
| `mypy --strict src` | Success: no issues found in 42 source files |
| `python benchmarks/run.py` | exit 0; 15 cases (vulnerable 6, safe 7, adversarial 2); scan complete, 15/15 files; NEX007: TP 8, FP 0, FN 1 (1 known miss, BM-NEX007-0202); counts only (15 < 20, DEC-0002) |

New-module coverage (combined): json_config 99%, config_view 96%, frameworks/mcp/config 99%, endpoints 99%,
python_client 100%, nex007 99%, workers 98%, scan 96%.

Not run: Linux, Python 3.12, real-world repositories.

## 5. Known FPs / FNs

- FP risk (expected largest): `https://` servers that negotiate OAuth at connect time -> medium/medium finding.
  Gateway/VPN/mesh auth invisible. Claude Desktop `url` entries possibly ignored by the client (confidence medium).
- FN: env/templated URLs; Python URL via variable/constant (BM-NEX007-0202, fixture adversarial/case_011);
  MultiServerMCPClient (case_012); Windsurf `serverUrl` and other unverified clients (case_013); YAML/TOML configs;
  TS clients; configs outside the repo or added via CLI/UI; server-side 0.0.0.0 binds; https tokens in URL query.

## 6. Gaps

- No YAML parser (step 4 left `.yaml/.toml` partial). No config-level per-finding suppression for JSON.
- Corpus below DEC-0002's 20 cases; no independent labels; no real-world triage; no held-out set.
- Harness writes no `metrics.json` / baseline comparison yet (TASK-0025 items).

## 7. Inputs for step 5 (SARIF + HTML reporters)

- NEX007 findings have **no flow**: SARIF `codeFlows` omitted; use `locations[0]` (column is a 1-based UTF-8 byte
  offset - for JSON too; convert to `unicodeCodePoints` or declare `columnKind`). Evidence items
  (`recognised_as`, `config_value`, `auth_search`, `duplicate_keys`) map to `result.properties` or
  `relatedLocations`-free text; all are untrusted/display-safe.
- `RuleMeta.doc.status_note` should appear as rule help text; SARIF `defaultConfiguration.enabled = false` for
  experimental rules; `properties.tags` = ASI labels; CWE as taxa or tags.
- `ScanResult.frameworks` is new header data for HTML. JSON report schema unchanged (frameworks not in it).
- Golden inputs: reuse `tests/golden/json/NEX007-finding.json` scenario via `rule_fixtures.scan_virtual`.

## 8. Inputs for step 6 (GitHub Action)

- NEX007 is off by default: the Action README must say to add `rules.enabled: [NEX007]` (or `ASI07`) to
  `.nexvul.yml`; in CI repo config may enable (tighten) rules.
- `.json` findings cannot carry inline suppressions; PR annotations should link `docs/rules/NEX007.md` and the
  `exclude`/`rules.disabled` route (note `rules.disabled` is not applied in CI per DEC-0004 §1).
- Committed `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` are the target files; annotation line = the
  `url` key line.
- Run `python benchmarks/run.py` as a non-blocking CI job until the corpus reaches 20 labelled cases.
