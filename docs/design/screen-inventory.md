# nexvul — Screen Inventory

> Status: **Proposed design** (Phase 0). Nothing here is implemented.
> Owner: Design (Dave). Date: 2026-10-08.
> **IDs are permanent.** Never renumber. A screen that is replaced is marked *superseded by Xnn* and keeps its row.
> Tickets, reviews and test names use these IDs (`test_T06_partial_no_findings_never_says_no_findings`).

## 0. Conventions

**Prefixes.** One letter per surface.

| Prefix | Surface |
|--------|---------|
| `T` | Terminal: `nexvul scan` output states |
| `U` | Terminal: utility commands (`rules`, `explain`, `doctor`, `version`, `--help`) |
| `K` | pre-commit hook output |
| `C` | Configuration UX: `.nexvul.yml`, inline suppressions, config messages |
| `H` | Self-contained HTML report |
| `J` | Machine output contracts as a human meets them (JSON, SARIF files) |
| `G` | GitHub code scanning UI (rendered from SARIF) |
| `A` | GitHub Action: job summary, annotations, check conclusion, Action errors |
| `D` | README and documentation landing pages |

**Priority.** **P0** cannot ship without · **P1** should ship, workaround exists · **P2** later ·
**BLOCKED** needs a product decision first (decision ID given).

**Release slice.** Phase 2 thin slice (roadmap) = terminal + JSON + SARIF + HTML. Action and pre-commit are
Phase 6. Priorities below are relative to the surface's own phase.

**Scan status vocabulary (used everywhere, never paraphrased).**

| Status | Meaning | Shown as |
|--------|---------|----------|
| `COMPLETE` | Every discovered, non-excluded regular file was parsed and analysed with no limit, budget or truncation hit | `Scan complete` |
| `PARTIAL` | Something discovered was not fully analysed (skip, parse failure, timeout, limit, budget, truncation) | `PARTIAL SCAN` |
| `FAILED` | No usable result (nothing analysable, or the engine could not run rules) | `SCAN FAILED` |

Outcome is a second, independent axis: *findings at/above threshold* or not. Every screen shows both axes.
*Why two axes:* "0 findings" and "complete" are different facts; collapsing them into one "clean/dirty" verdict
is exactly the false-assurance failure the threat model ranks highest.

**Universal requirements for every screen** (not repeated per row):

- R1. Any text originating in the scanned repository (paths, identifiers, snippets, justifications, framework
  names read from manifests) passes through the single sanitiser (SR-10) before display. Terminal: Rich `Text`
  only, never markup strings. HTML: `textContent` / autoescape only. Markdown surfaces: never contains
  repo text except inside escaped code spans (see `github-and-action.md` §5).
- R2. The completeness summary is rendered from trusted accounting, **after** findings, and is never suppressed
  by `--quiet`.
- R3. The words in `design-system.md` §8 (banned phrases) never appear in nexvul-authored strings, except the
  fixed disclaimer sentence.
- R4. Severity is never conveyed by colour alone: label text and the severity meter glyph are always present.
- R5. With `NO_COLOR` set, `--no-color`, `TERM=dumb`, or stdout not a TTY: zero ESC bytes in output.
- R6. stdout carries the result; stderr carries progress and diagnostics. `nexvul scan --format json > f.json`
  must produce a valid file even when warnings occur.

---

## 1. `T` — Terminal: `nexvul scan`

Mock-ups at 80 and 120 columns: [`terminal-mockups.md`](terminal-mockups.md).

| ID | State | Trigger | Exit | Pri | Specification (what, and why) |
|----|-------|---------|------|-----|-------------------------------|
| T01 | Scanning (progress) | TTY, scan running | — | P0 | One self-overwriting line on **stderr**: phase (`Discovering` → `Parsing` → `Analysing` → `Reporting`), `n/N files`, elapsed. *Why one line:* per-file output scrolls findings off screen and leaks nothing useful. Not shown when non-TTY (T15) — a CI log gets one line per phase instead. Never shows filenames (avoids hostile names flashing on screen before sanitising matters). |
| T02 | Complete, no findings | status COMPLETE, 0 active findings | 0 | P0 | Header block, then *"No findings from enabled rules. This does not prove the application is secure."* (fixed string, SR-18), then what was checked: files analysed, rules run (`25 of 25 enabled`), frameworks recognised, suppressions applied. Neutral colour, **never green**, no tick glyph. *Why:* the most dangerous screen in the product; it must read as a scope statement, not a verdict. |
| T03 | Complete, findings below threshold | COMPLETE, findings exist, none ≥ `fail_on` | 0 | P0 | Same as T04 but the final line states *"0 findings at or above `high` (fail-on). 3 lower-severity findings listed above."* *Why:* exit 0 with findings must not read as a pass; the developer should still see there is work. |
| T04 | Complete, findings at/above threshold | COMPLETE, ≥1 finding ≥ `fail_on` | 1 | P0 | Header → findings grouped by severity (critical first) → suppressed block (if any) → completeness → result line. Each finding: severity label + meter, `NEX0nn`, title, ASI tags, `path:line:col`, one-sentence message, numbered flow (source → steps → sink), one-line fix, `nexvul explain NEX0nn` hint once per rule. *Why source → flow → sink:* brief §24; the developer must see why nexvul believes the data gets there, not just that it does. |
| T05 | Partial, with findings | PARTIAL, ≥1 finding | 3 | P0 | As T04, then the partial block: counts by skip reason, first 5 paths (sanitised), then the fixed banner as the **last line**: *"PARTIAL SCAN — 4 of 312 files not analysed. This result is not a clean bill of health."* (threat model §7). *Why last:* the last line is what people read and what CI log tails show. |
| T06 | Partial, no findings | PARTIAL, 0 active findings | 3 | P0 | **Must not** print "No findings". Prints *"No findings in the 308 files that were analysed. 4 files were not analysed."* then the partial banner. *Why:* "no findings" + partial is the textbook false clean (T-22). Test name must assert the absence of the T02 sentence. |
| T07 | Failed | engine could not produce a result (all parsers failed, worker pool could not start, rule table integrity check failed) | 3 | P0 | `SCAN FAILED`, one-sentence cause, what to try (`nexvul doctor`). No findings list, even partial ones. Exit 3 not 4 when the cause is the input (e.g. every file unparseable); 4 when it is nexvul (see §9). |
| T08 | Parse errors (summary) | ≥1 file `parse_error` / `parser_crashed` | 3 | P0 | Part of T05/T06 partial block: `Parse errors: 2 (python 2, typescript 0)`. Hint: `--verbose` to list. *Why counts by default, list on demand:* a file-count bomb must not flood the screen (§7 rule 7), but the count can never be hidden. |
| T09 | Config error | `.nexvul.yml` invalid: unknown key, wrong type, YAML anchors/aliases, size cap, path outside repo | 2 | P0 | `Config error in .nexvul.yml:7:3` + key + what was expected + the accepted values. Nothing is scanned. *Why refuse rather than ignore the bad key:* a mistyped `exclude` silently ignored is a scan the user did not ask for; a mistyped `rules.disabled` silently ignored is fine, but the user cannot tell which they did. |
| T10 | Usage error | bad flag, unknown `--format`, path missing or outside scan root, conflicting flags | 2 | P0 | One line of error, one line of the closest valid usage, `Run nexvul scan --help for all options.` Did-you-mean for paths and flags (edit distance ≤ 2). |
| T11 | Internal error | uncaught exception in nexvul | 4 | P0 | `nexvul stopped unexpectedly (internal error).` Exception **type** and repo-relative path being processed only (SR-24: no file content, no absolute paths). Bug-report URL. `--debug` shows the traceback. *Why no traceback by default:* traces can echo file content; and a traceback reads as "my code broke it" to a developer. |
| T12 | `--verbose` | flag | per result | P0 | Adds: effective config with source per key, plugin list (empty in v1), full skip list (capped at 200, with "and N more"), per-phase timings, cross-file budget usage, analysis-limited notes (dynamic imports/exec found). Findings section unchanged. |
| T13 | `--explain NEX0nn` (inline) | scan flag | per result | P1 | Findings for that rule print the full `explain` body (U03 layout) inline after the first occurrence. Other rules print normally. *Why:* lets a developer learn one rule in context without a second command. |
| T14 | `--quiet` | flag | per result | P0 | Only the result block: counts by severity, status line, partial banner if any. Never removes the disclaimer or partial banner (R2). |
| T15 | Plain output (non-TTY / `NO_COLOR` / `TERM=dumb` / CI) | env | per result | P0 | Same content, no ESC bytes, ASCII severity meter (`[###.]`), no box-drawing, no progress line, one line per phase on stderr. Wrapping at 100 columns when width is unknown. *Why ASCII:* CI log viewers and Windows code pages mangle box-drawing. |
| T16 | Narrow terminal (< 80 columns) | `COLUMNS` < 80 | per result | P1 | Stacked layout: location on its own line, flow steps one per line, no right-aligned columns. Minimum supported 40 columns; below that, plain T15 layout without wrapping. |
| T17 | Suppressions & weakened-config block | ≥1 suppressed finding, or ≥1 weakening | per result | P0 | Section `Suppressed (3)`: rule, location, kind (`inline` / `config` / `baseline`), justification (escaped, ≤120 chars). Then `Protections weakened by repository configuration` if any, each with *applied / not applied* and why. Then stale suppressions (matched nothing). *Why a block, not a footnote:* suppressions are claims by the person whose code was flagged (T-17). |
| T18 | Nothing to analyse | 0 analysable files discovered | 3 | P0 | `SCAN FAILED — nothing to analyse in ./path`. Shows what was found (`12 files: 9 .md, 3 .json not recognised as agent configs`) and two likely causes. *Why exit 3:* exit 0 here would pass CI for a misconfigured path forever. Decision OD-05. |
| T19 | No framework recognised | files analysed, 0 frameworks | per result | P0 | Header `Frameworks: none recognised`; completeness note: *"Framework-specific rules (18 of 25) had nothing to attach to. Supported: LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP."* Does **not** make the scan partial. *Why:* the commonest false-clean for an unsupported framework. |
| T20 | Interrupted | SIGINT / SIGTERM | 130 / 143 | P0 | `Scan interrupted. No result was produced.` No findings printed. JSON/SARIF output file not written (atomic write means the old file, if any, is untouched). |
| T21 | Machine format written | `--format json|sarif|html --output f` | per result | P0 | stdout: nothing (or the file path when TTY). stderr: the same status line as T02–T06 in one line: `nexvul: PARTIAL SCAN — 2 high, 1 medium — wrote results.sarif`. *Why:* someone running a SARIF scan locally must still see partial status without opening the file. |
| T22 | Output refused | `--output` names an existing non-nexvul file, a symlink, or a path inside `.git/` | 2 | P0 | `Refusing to overwrite README.md: it is not a nexvul report. Use --force to overwrite.` Symlink/`.git` cases have no `--force` path. (SR-07, SR-14) |
| T23 | CI mode header | `CI=true`, `GITHUB_ACTIONS=true` or `--ci` | per result | P0 | Header adds `Mode: CI (auto-detected from GITHUB_ACTIONS)` and `Config: .nexvul.yml from base ref 3f2c1a9 (sha256 …)`; weakening rules per OD-01. |
| T24 | Staged-file scan | invoked with file arguments (pre-commit) | per result | P1 | See K01–K04. Header `Scope: 3 staged files (cross-file analysis off)`. |
| T25 | Global limit hit | wall-clock, `max_files`, total bytes, findings cap | 3 | P0 | Partial block names the limit and its value: `Limit reached: max_files (1000 of 1,412 discovered)`. Raising a limit is shown as a CLI flag, never as an edit to repo config (repo config can only lower limits). |

## 2. `U` — Utility commands

| ID | Command / state | Exit | Pri | Specification |
|----|-----------------|------|-----|---------------|
| U01 | `nexvul rules` | 0 | P0 | Table: ID, title, ASI tags (ordered per mapping decision OD-02), default severity, confidence ceiling, status (`default` / `experimental` / `off`), frameworks. Sorted by ID. Footer: `25 rules · 19 on by default · nexvul explain <ID> for details`. *Why status column:* contributors and AppSec need to know which rules ran by default. |
| U02 | `nexvul rules --asi ASI07` / `--status experimental` / `--json` | 0 | P1 | Filtered table; empty filter result prints `No rules match --asi ASI03. nexvul currently maps rules to ASI02, ASI03, ASI05–ASI10.` (no-results is distinct from no-data). |
| U03 | `nexvul explain NEX0nn` | 0 | P0 | Sections in fixed order: title line · What it looks for · Why it matters · Example (flagged / not flagged, side by side ≥ 120 cols, stacked below) · How to fix · What this rule does not detect · Severity & confidence (with modifiers) · OWASP mapping (+ CWE) · Suppressing this finding (exact syntax, rule ID pre-filled) · References. Content only from built-in rule docs. Paged through `$PAGER` on a TTY when longer than the screen. |
| U04 | `explain` unknown ID | 2 | P0 | `NEX060 is not a nexvul rule. Did you mean NEX006 (A2A / agent HTTP endpoint without authentication)?` Lower-case and missing-zero inputs (`nex6`) normalised. |
| U05 | `nexvul doctor` — all checks pass | 0 | P0 | Checklist with `ok` / `warn` / `fail` words (not ticks): nexvul version + install path + distribution name (T-26), Python version, parsers available (Python ast, tree-sitter JS/TS grammar versions), worker sandbox can start, cache dir + permissions, rule table integrity hash, plugins (none loaded; discovered entry points listed but not loaded), network: "nexvul makes no network connections" (statement, not a test of the network). Last line: `All checks passed. This checks nexvul's installation, not your code.` |
| U06 | `doctor` — problems found | 1 | P0 | Same list with `warn`/`fail` rows each followed by one line of fix. Key warnings: running inside the scan root's venv (T-25), a `nexvul.rules` entry point from an unexpected distribution, cache dir world-readable, tree-sitter grammar missing (JS/TS files will be skipped). |
| U07 | `nexvul version` / `--version` | 0 | P0 | `nexvul 0.1.0 (rules 2026.10.1, sha256:9c1e…) Python 3.12.6`. One line, scriptable. `--json` gives fields. *Why rule-pack hash:* SR-27 auditability; two people comparing results must know whether rules matched. |
| U08 | `nexvul --help`, `nexvul scan --help` | 0 | P0 | Commands/flags grouped: Output, Scope, Thresholds, CI, Diagnostics. Ends with exit-code table (§9) in 5 lines. *Why exit codes in help:* CI authors read `--help`, not docs. |
| U09 | `explain` withdrawn rule | 0 | P2 | `NEX0nn was withdrawn in 0.4.0: <reason>. Replaced by NEX0mm.` IDs are never reused. |

## 3. `K` — pre-commit hook

| ID | State | Exit | Pri | Specification |
|----|-------|------|-----|---------------|
| K01 | Pass | 0 | P1 | pre-commit prints its own `nexvul....Passed`. nexvul adds nothing unless suppressions exist (then one line: `1 suppressed finding (NEX006) — see nexvul scan`). *Why silent:* hooks that talk on success get disabled. |
| K02 | Findings at/above threshold | 1 | P1 | Compact list, one finding per 2 lines (`path:line  SEV  NEX0nn  title` / `  fix: …`), then K03 line, then `Commit blocked by nexvul (fail-on: high).` |
| K03 | Scope reminder | — | P1 | Always the last line when anything prints: `Staged-file scan: cross-file flows not checked. Run nexvul scan . for a full scan.` |
| K04 | Nothing relevant staged | 0 | P1 | pre-commit shows `(no files to check)Skipped`; nexvul is not invoked (types filter). |
| K05 | Partial (staged file failed to parse) | 3 | P1 | Commit blocked with the parse-error line. *Why block:* a syntax-error file the developer is committing is cheap to fix now; could be configured warn-only via user config. |

## 4. `C` — Configuration and suppressions

| ID | Item | Pri | Specification |
|----|------|-----|---------------|
| C01 | `.nexvul.yml` (annotated example) | P0 | Keys from brief §14: `severity.fail_on`, `rules.enabled` (rule IDs or ASI IDs), `rules.disabled`, `exclude` (globs, repo-relative), `frameworks.auto_detect`, `analysis.cross_file`, `analysis.max_files`. Plus proposed `suppressions.require_justification`. Documented example in `terminal-mockups.md` §C01 with every key commented with *what weakens vs strengthens*. Unknown keys are errors (T09). |
| C02 | Config validation messages | P0 | Pattern: `Config error in <file>:<line>:<col>: <key>: <problem>. Expected <type/values>.` Examples for unknown key (with did-you-mean), wrong type, anchors/aliases (`YAML anchors and aliases are not allowed in .nexvul.yml`), path escaping repo, file too large. |
| C03 | Inline suppression syntax | P0 | Python/YAML: `# nexvul: ignore[NEX006] -- <justification>`. JS/TS: `// nexvul: ignore[NEX006] -- <justification>`. Multiple IDs: `ignore[NEX006,NEX010]`. Applies to the same line or the next non-comment line. Justification: free text after ` -- `, 10–300 chars. *Why `--`:* a visible, typeable separator; avoids quoting. Syntax final per OD-04. |
| C04 | Missing justification | P0 | CI default: finding stays **active**; message in T17 / A01. Local default: suppression applies, T17 shows `(no justification)` in the justification column. |
| C05 | Rejected suppression | P0 | Blanket (no rule ID), unknown rule ID, hidden/bidi characters, inside a string literal (silently not a comment). Each: finding stays active, one warning line naming file:line and reason. |
| C06 | Weakened-by-repo-config notice | P0 | Shown in T17, A01, H07, SARIF `toolConfigurationNotifications`. Format: `<key>: <value> — applied (trusted source: base ref)` or `— not applied (pull request head; CI mode)`. |
| C07 | `nexvul init` (write a commented `.nexvul.yml`) | P2 | Not in brief; proposed as OD-12. Would write C01 with all keys commented out. |
| C08 | Baseline file (`nexvul baseline create`) | P2 | Roadmap Phase 6 mentions baseline mode. Baseline lives at a path set by trusted config; baselined findings appear as `suppressed (baseline)` and count in completeness. Not designed further until scheduled. |

## 5. `H` — HTML report

Built on `assets/report-preview.html` (dark-first, mono numerals, card findings). Changes from that mock-up are
listed in `design-system.md` §10 with reasons and need sign-off.

**Page order (top to bottom), fixed.** *Why fixed:* the order is the argument — scope first, then findings,
then how to read them.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ [mark] nexvul   my-agent-project/ · commit 3f2c1a9 · 2026-10-08 14:32 UTC    │ H01 header
├──────────────────────────────────────────────────────────────────────────────┤
│ ▓▓ PARTIAL SCAN — 4 of 312 files not analysed. This result is not a clean    │ H03 banner
│    bill of health.  [See what was not analysed ↓]                            │ (partial/failed only)
├──────────────────────────────────────────────────────────────────────────────┤
│ STATUS        FINDINGS     CRITICAL  HIGH   MEDIUM  LOW    SUPPRESSED        │ H01 tiles
│ Partial       12           2 ████    4 ███░ 4 ██░░  2 █░░░ 3                 │
├──────────────────────────────────────────────────────────────────────────────┤
│ What was checked   308/312 files · 25/25 rules · LangGraph, MCP · cross-file │ H07 strip
├──────────────────────────────────────────────────────────────────────────────┤
│ Group by: (Severity) ASI  File      Filter: [ ] show low  [ ] show suppressed│ H08
├──────────────────────────────────────────────────────────────────────────────┤
│ CRITICAL ████  NEX020  Shell execution and unrestricted network on one agent │ H05 card
│                ASI10 ASI05 · confidence medium        agent/tools.py:18      │ (collapsed)
│ HIGH     ███░  NEX002  External content indexed into a vector store          │
│   ▾ expanded: Source → Flow → Sink → Why it matters → How to fix → Not covered│ H05 expanded
├──────────────────────────────────────────────────────────────────────────────┤
│ Suppressed (3)                                                               │ H06
├──────────────────────────────────────────────────────────────────────────────┤
│ Scan completeness & provenance (full)                                        │ H07 full
├──────────────────────────────────────────────────────────────────────────────┤
│ nexvul 0.1.0 · rules sha256:9c1e… · A clean nexvul result does not prove     │ footer
│ that an application is secure.                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

| ID | State / section | Pri | Specification |
|----|-----------------|-----|---------------|
| H01 | Overview, complete with findings | P0 | Header: project dir name (sanitised), commit SHA if known, UTC timestamp, nexvul version. Tiles: Status, Findings, Critical, High, Medium, Low, Suppressed. **Removed** from the mock-up: the "OWASP Coverage ASI06–10" tile (implies coverage of whole categories; see design-system §10). Severity bar keeps segments but each segment has a text label on hover *and* the tiles carry the meter glyph. |
| H02 | Overview, complete, no findings | P0 | Findings tile shows `0` in neutral ink, not green. Below tiles, the fixed sentence from T02 at body size, not a footnote. The findings area shows the "What was checked" strip expanded by default. *Why:* zero findings is the moment the scope statement matters most. |
| H03 | Partial banner | P0 | Non-dismissable (no close control), sticky on scroll, amber with a diagonal hatch pattern (pattern = non-colour cue), text from threat model §7, link to H07. Present on every page of print output. |
| H04 | Failed | P0 | Red banner `SCAN FAILED — <cause>`; no tiles except Status; H07 completeness shown. A report is still written so CI artifacts explain the failure. |
| H05 | Finding card (collapsed / expanded) | P0 | Collapsed: severity label + meter, rule ID, title, ASI tags, confidence word, `path:line`. Expanded (native `<details>`; works without JS): **Source** (code span), **Flow** (ordered list, each step `path:line` + code span; source and sink marked with words "source"/"sink", not only colour), **Sink**, **Why it matters** (rule-doc text), **How to fix** (rule-doc text + example), **What this rule does not detect**, **Suppress** (copyable syntax). Snippets ≤ 3 lines, secrets redacted (T-24). |
| H06 | Suppressed findings | P0 | Collapsed `<details>` with count in summary; table: rule, location, kind, justification (escaped), *added in this change* marker when known. Stale suppressions listed beneath. |
| H07 | Completeness & provenance | P0 | Full threat-model §7 block: status, files discovered/analysed, skipped by reason (table), first 50 skipped paths + "and N more", limits hit, budgets exhausted, findings truncated, suppression counts, protections weakened by repo config, config sources + sha256, plugins, dynamic constructs not analysed, nexvul version, rule-pack hash, Python version, start/end time. A one-line strip version sits under the tiles (H01). |
| H08 | Group / filter controls | P1 | Group by Severity (default) / ASI / File. Filters: show low & info, show suppressed. Controls are progressive enhancement: with JS blocked by CSP misconfiguration or disabled, the page shows everything grouped by severity (H10). Filter state in URL fragment only (no storage). |
| H09 | Print / PDF | P1 | `@media print`: light palette, all `<details>` expanded, banner repeated at the top of the first page, page footer with disclaimer. A4 portrait. |
| H10 | No-JS rendering | P0 | All content present in static HTML; JS only toggles grouping. *Why:* CSP-hashed script may be blocked in some viewers (CI artifact previewers); the report must still be complete. |
| H11 | Light theme | P0 | `prefers-color-scheme: light` and `data-theme` override as in the mock-up; tokens in `tokens.json`. |
| H12 | Narrow viewport (≤ 600px) | P1 | Tiles 2-up; finding card single column; flow steps wrap; 16px gutters; no horizontal page scroll (code spans scroll inside their own box). |
| H13 | Hostile content | P0 | Reference fixture rendering: filename `<img src=x onerror=alert(1)>.py`, a bidi-override path, a 4,000-char identifier, a snippet containing `</script>`. All render as visible escaped text (`\u{202E}` shown as a visible token), truncated with `…` + hash suffix. This is a test page, not a user screen; it is the acceptance fixture for SR-13. |
| H14 | App shell: side menu + top bar (DEC-0009) | P0 | Left menu: Overview, Findings, Frameworks and agent map, Rules, Suppressions, Scan history, Settings, Help and docs, each with a count. Menu footer states "Local file. No account, no sign-in, no network." Top bar: scan target, commit, UTC time, status pill (`COMPLETE` neutral outline / `PARTIAL SCAN` hatched amber, word always present), exit-code chip, theme toggle. *Why no account screens:* the report is a file on the user's disk; an auth surface needs a server and adds credential handling to a security tool (DEC-0009). |
| H15 | Narrow menu (≤ 900 px) | P1 | Menu collapses behind a 40×40 button (`aria-expanded`), opens as a drawer over a scrim; Esc and the close button return focus to the menu button. Without JS the menu renders inline above the content. At ≤ 600 px tiles go 2-up and the top bar keeps target + status word + theme only. |
| H16 | Findings view | P0 | Filter bar: severity chips (word + meter + count, `aria-pressed`), ASI select, rule select, file-contains text (`/` focuses it). List of H05 cards; the first is open. Expanded card: message, numbered flow (source/step/sink as words), why, fix, what nexvul looked for and did not find, side column with locations, rule, not-detected, copyable suppression and `explain` lines. Deep links `#findings/F3`, `#findings/sev=high`, `#findings/rule=NEX015`. |
| H17 | Findings: no results for filters | P0 | "No findings match these filters. 9 findings are hidden by the current filters. This is not a scan result." + Clear filters. *Why distinct from H02:* "no results" must never read like "no findings". |
| H18 | Frameworks and agent map | P1 | Framework cards (version range, files, how recognised, rules attached) + "Not recognised" line; SVG graph Inputs → Agents → Tools → Sensitive sinks with rule pills naming rule and severity in words; the same data as an accessible table with "Controls found". Note: controls outside the repo are not visible. |
| H19 | Rules view | P1 | NEX001–NEX025: ID, title, ASI tags (`provisional` marker for NEX016–NEX025 per OD-02), class, default severity, state in this run (runs / off + source), findings count (links to H16), readiness (`design only` until implemented). ASI filter. |
| H20 | Suppressions view | P0 | Tiles: applied, added on this branch, rejected, stale. Table: rule, location, kind, justification (escaped, ≤120 chars, hidden characters as code points), status with consequence ("In CI this suppression is NOT applied"), "Added on this branch" flag. Weakened-config list with CI behaviour. Copyable syntax. Supersedes H06's placement; H06 content rules still apply. |
| H21 | Scan history (this run only) | P1 | One run only: start/end, duration, result + exit code, mode, branch/commit, "Compared with: nothing: no earlier run is stored". Time-by-phase bar with labelled legend. Not-analysed table (partial). Full H07 provenance table. "Compare runs yourself" with the JSON command. *Why one run:* no history store and no server in v1 (DEC-0009). |
| H22 | Settings (read-only) | P0 | Effective configuration with value, source (CLI flag / `.nexvul.yml:line` / default), whether it weakens the scan, and what happens in CI mode. "Not applied in CI mode" panel. Rule on/off grid with source. "Change a setting" copyable commands and YAML. Never writes config or source files. |
| H23 | Help and docs | P1 | Reading a finding, status vocabulary, severity table, exit codes, commands, privacy statement ("no account, sign-in or server"). |
| H24 | Display preferences | P1 | Theme (system / light / dark), density, show low and info, wrap code. Stored only in this browser's localStorage key `nexvul.report.prefs`, every access in try/catch; when storage is blocked the page says preferences last until the tab closes. Preferences never change the scan or result. Light (white page) is the default. |

## 6. `J` — Machine outputs, as a human meets them

| ID | Item | Pri | Specification |
|----|------|-----|---------------|
| J01 | JSON file | P0 | Top-level keys in this order: `nexvul` (version, rules hash, python), `scan` (target, commit, started/ended), `completeness` (threat model §7, required), `summary` (counts by severity, status, threshold, outcome), `findings[]`, `suppressed[]`. Repo-derived strings in findings are under `evidence.*` and flagged `untrusted: true` (T-23). Pretty-printed when written to a TTY, compact otherwise. |
| J02 | SARIF file | P0 | See `github-and-action.md`. `executionSuccessful: false` when not COMPLETE. |

## 7. `G` — GitHub code scanning (rendered from SARIF)

Specified in [`github-and-action.md`](github-and-action.md) §§2–4.

| ID | View | Pri |
|----|------|-----|
| G01 | Alert list row (Security → Code scanning, PR checks list) | P0 |
| G02 | Alert detail: message, location, code flow ("Show paths") | P0 |
| G03 | Rule help panel (`help.markdown`) | P0 |
| G04 | Suppressed-in-source alert | P0 |
| G05 | Tool status / run notifications (partial, truncated, weakened config) | P0 |

## 8. `A` — GitHub Action

Specified in [`github-and-action.md`](github-and-action.md) §§5–7.

| ID | View | Pri |
|----|------|-----|
| A01 | Job summary: findings at/above threshold (exit 1) | P0 |
| A02 | Job summary: complete, none at/above threshold (exit 0) | P0 |
| A03 | Job summary: partial or failed (exit 3) | P0 |
| A04 | PR annotations (code scanning annotations on "Files changed") | P0 |
| A05 | Job / check conclusion and its one-line title | P0 |
| A06 | Refusal: `pull_request_target` / `workflow_run` with untrusted checkout | P0 |
| A07 | SARIF upload failure (permissions, fork PR, size, duplicate category) | P0 |
| A08 | Input / config error (exit 2) | P0 |
| A09 | Internal error (exit 4) | P0 |

## 9. Exit-code contract (public API once released)

Adopts the threat model proposal (T-20, SR-19) and adds precedence, signals and the nothing-to-analyse case.
Decision OD-06 confirms; OD-05 covers T18.

| Code | Name | When | Screens |
|------|------|------|---------|
| `0` | Complete, below threshold | Status COMPLETE and no active finding ≥ `fail_on` (findings below threshold may exist) | T02, T03, A02, K01 |
| `1` | Findings at/above threshold | Status COMPLETE and ≥1 active finding ≥ `fail_on` | T04, A01, K02 |
| `2` | Usage or configuration error | Bad flag, bad path, invalid config, refused output. Nothing was scanned | T09, T10, T22, U04, A08 |
| `3` | Scan incomplete | Status PARTIAL or FAILED for input reasons, including nothing to analyse | T05–T08, T18, T25, A03, K05 |
| `4` | Internal error | nexvul bug or environment fault (worker cannot start, integrity check failed) | T07 (engine cause), T11, A09 |
| `130` / `143` | Interrupted | SIGINT / SIGTERM; no result produced | T20 |

**Precedence when several apply:** `2` > `4` > `3` > `1` > `0`. A partial scan that also has findings ≥ threshold
exits **3**, and its output still lists every finding. *Why 3 beats 1:* the exit code answers "can this result
be used as a gate?" first. A partial result cannot, in either direction, and a script that alerts on `3` must
never miss a partial scan because findings happened to exist. (Recommendation; OD-06.)

**`fail_on: never`** (or `--fail-on never`): `1` is never returned; `3` still is unless trusted config sets
`completeness.fail_on_partial: false` (OD-06; threat-model handoff D4).

`doctor` exits `0` (all ok) or `1` (any warn/fail). `explain`/`rules`/`version` exit `0` or `2`.

## 10. `D` — README and docs landing

| ID | Page / block | Pri | Specification |
|----|--------------|-----|---------------|
| D01 | README above the fold | P0 | Wordmark; one-line value statement (≤ 12 words, e.g. *"Static checks for risky patterns in AI-agent code and MCP configs."*); 3 badges max (PyPI version, licence, CI) — **no "OWASP" badge** (reads as endorsement); install line; scan line; terminal screenshot of T04 (not T02); the sentence *"A clean result does not prove your application is secure."*; "Runs locally. No account, no telemetry, no network." |
| D02 | Quickstart | P0 | `pipx install nexvul` → `nexvul scan .` → reading one finding → `nexvul explain` → HTML report. Each step shows expected output. |
| D03 | What nexvul does not do | P0 | From security-model non-guarantees, in user words, on the README (not only in docs). |
| D04 | Rule reference page `docs/rules/NEX0nn.md` | P0 | Same sections and order as U03 and G03 (one source, three renderings). |
| D05 | CONTRIBUTING → Propose a rule | P1 | Lifecycle as numbered gates with the evidence each needs; proposal template; how IDs are allocated; how to run per-rule benchmark locally. |
| D06 | CI and pre-commit snippets | P0 | Reference workflow (security-model "Safe CI usage") and pre-commit snippet pinned by SHA; exit-code table; "do not use `continue-on-error`". |
| D07 | Rules index | P1 | Generated from rule metadata: table as U01, grouped by ASI, each with "does not detect" one-liner. |
| D08 | Comparison table | P2 | Versus Semgrep/Bandit/agent scanners; only claims with a linked artefact (benchmark run). Omitted until benchmark numbers exist (brief §33). |

## 11. State counts (checked, not assumed)

| Surface | States designed | Notes |
|---------|-----------------|-------|
| `scan` result | 3 statuses × 2 outcomes = 6 meaningful combinations; FAILED has no outcome axis → 5 result screens (T02, T03, T04, T05, T06) + T07 + T18 | T06 is the state most likely to be built wrong |
| `scan` errors | config (T09), usage (T10), internal (T11), interrupted (T20), output refused (T22) | each has an exit code |
| `scan` modes | default, `--verbose`, `--quiet`, `--explain`, plain/CI, narrow, staged, machine-format | T12–T16, T21, T23, T24 |
| HTML report | complete+findings, complete+none, partial, failed, print, no-JS, light, narrow, hostile; app-shell views, filter-empty, narrow menu, read-only settings, prefs | H01–H24 |
| Job summary | exit 0, 1, 2, 3, 4, refused, upload failed | A01–A03, A06–A09 |
| `rules` | full, filtered, filtered-empty (no results), JSON | U01, U02 |
| `explain` | found, unknown, withdrawn | U03, U04, U09 |
| `doctor` | pass, warn/fail | U05, U06 |
