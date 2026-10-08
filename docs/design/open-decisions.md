# nexvul — Open Decisions for the Product Owner

> Status: **Awaiting decision.** Owner of this list: Design (Dave). Decider: Victor Ibhafidon (product owner).
> Date: 2026-10-08. Each item names the screens it blocks, the options, a recommendation and what users will
> notice either way. Items that duplicate an existing escalation reference it rather than re-deciding it.

## Summary

| ID | Decision | Blocking? | Blocks | Recommendation |
|----|----------|-----------|--------|----------------|
| OD-01 | Trust of repo-local `.nexvul.yml` in CI | **Blocking** | T17, T23, C01, C06, A01, H07 | Weakening keys only from base ref / explicit input |
| OD-02 | ASI labels for NEX016–NEX025 | **Blocking** | U01, U03, G03, H08, SARIF tags | Multi-label, ordered, ASI09/ASI10 always present |
| OD-03 | Justification required on inline suppressions | **Blocking** | C03, C04, T17, A01 | Optional locally, required in CI |
| OD-04 | Inline suppression syntax (public, hard to change) | **Blocking** | C03, U03, G03 | `# nexvul: ignore[NEX006] -- reason` |
| OD-05 | Exit code when there is nothing to analyse | **Blocking** | T18, A03 | Exit 3 |
| OD-06 | Exit-code contract and precedence | **Blocking** | all T, K, A | 0/1/2/3/4 + 130/143; precedence 2>4>3>1>0; partial = 3 locally and in CI |
| OD-07 | Per-finding severity vs GitHub's per-rule severity | **Blocking** | G01, G02, A01 | Rule default in badge; effective severity first in message |
| OD-08 | HTML report in v1 | **Blocking** | H01–H13 | Ship in the thin slice; SR-13 is a release blocker |
| OD-10 | Brand and visual deviations DV-1…DV-12 | **Blocking** for README/report visuals | D01, H01, brand | Approve all |
| OD-09 | Workflow-command annotations from the Action | Non-blocking | A04 | Not in v1 |
| OD-11 | Canonical repository owner / URLs | Non-blocking | T11, G03, A09 | Decide before first release |
| OD-12 | `nexvul init` command | Non-blocking | C07 | Defer to P2 |
| OD-13 | Info-level findings in SARIF | Non-blocking | G01, H01 | Not uploaded; shown in report "Context" |
| OD-14 | Partial staged scan blocks the commit | Non-blocking | K05 | Block by default |
| OD-15 | Default `fail-on` | Non-blocking | A05, C01, D06 | `high` |
| OD-16 | Inline `--explain` flag kept alongside `explain` command | Non-blocking | T13 | Keep (brief §8 lists it) |

---

## Blocking

### OD-01 — Trust of repo-local `.nexvul.yml` in CI
*Same question as threat-model handoff D1.*

- **Why it matters to the user:** a pull request can edit `.nexvul.yml` to disable the rule that flags it. If
  CI honours that, nexvul turns an attack into a green check.
- **Options:** (a) honour everything; (b) in CI apply only *strengthening* keys from PR head, *weakening* keys
  only from the base branch or an explicit `config:` input; (c) ignore repo config in CI.
- **Recommendation: (b).** Screens T17/T23/A01 are designed for it: they list each weakening with *applied* or
  *NOT APPLIED (pull request head; CI mode)*.
- **What users will notice:** a PR that changes `.nexvul.yml` sees its change take effect only after merge. The
  job summary tells them so, in the Configuration section, on that PR.

### OD-02 — ASI labels for NEX016–NEX025
*Same question as `docs/research/open-questions-security.md` Q1/Q2.*

- **Why it matters:** labels appear in `nexvul rules`, rule help, SARIF tags, report grouping and
  `rules.enabled: [ASI09]` config. Changing them after release breaks configs and alert filters.
- **Options:** keep ASI09/ASI10 primary (A); re-map primary to ASI02/ASI03/ASI05 (B); multi-label with
  ordering (C).
- **Recommendation: (C)**, with ASI09 always included on NEX016–NEX019 and ASI10 first only on NEX020/NEX025.
  Rule help states that nexvul covers only the "missing confirmation" slice of ASI09.
- **Design consequence:** grouping by ASI in the HTML report (H08) shows a multi-label finding under its first
  label, with the others as tags; counts per ASI are labelled "by first label" to avoid double counting.
- **Until decided:** U01 prints "ASI labels for NEX016–NEX025 are provisional".

### OD-03 — Justification on inline suppressions
*Threat-model handoff D2/D3.*

- **Options:** optional; always required; optional locally and required in CI.
- **Recommendation: optional locally, required in CI**; suppressions added in the PR are listed separately
  (A01 "Suppressions added in this pull request").
- **What users will notice:** a suppression without a reason works on their laptop and is ignored in CI with
  a message telling them to add `-- <reason>`. This is a deliberate speed bump.

### OD-04 — Inline suppression syntax

- **Why blocking:** once people write it into code, it cannot change without breaking every repository.
- **Options:**
  1. `# nexvul: ignore[NEX006] -- reason` (recommended)
  2. `# nexvul-ignore NEX006: reason` (Semgrep `nosemgrep`-like)
  3. `# noqa: NEX006` (familiar, but `noqa` is owned by flake8/ruff and those tools will warn on an unknown
     code; also carries no justification slot)
- **Recommendation: 1.** Namespaced (cannot collide with other linters), rule list in brackets (forces a rule
  ID), explicit justification separator, same shape in `#` and `//` comments.

### OD-05 — Exit code when there is nothing to analyse

- **Scenario:** `nexvul scan ./docs` or a CI `path:` typo. Zero analysable files.
- **Options:** (a) exit 0 with "No findings"; (b) exit 3 `SCAN FAILED — nothing to analyse`; (c) exit 2 as a
  usage error.
- **Recommendation: (b).** (a) is a permanent false-clean in CI for a misconfigured path; (c) is wrong because
  the path is valid, there is simply nothing nexvul understands in it.

### OD-06 — Exit-code contract and precedence
*Extends threat-model handoff D4/D10.*

- **Proposed contract:** `0` complete & below threshold · `1` findings at/above threshold · `2` usage/config
  error · `3` scan incomplete (partial, failed, nothing to analyse) · `4` internal error · `130`/`143` interrupted.
- **Precedence:** `2 > 4 > 3 > 1 > 0`. A partial scan with findings exits **3**, and still lists the findings.
- **Partial outside CI:** also exit 3 (not 0). *Why:* the same command must mean the same thing on a laptop and
  in CI; pre-commit and local scripts otherwise inherit a false clean.
- **Opt-out:** `fail-on-partial: false` only via trusted config or CLI/Action input, never repo config.
- **Alternative considered:** `1 > 3` (findings beat incompleteness). Rejected because a script that alerts on
  partial scans would silently miss every partial scan that also had findings.
- **What users will notice:** repos with unparseable or oversized files fail until those files are fixed or
  excluded by trusted config. This will be the most common early complaint; the A03 summary tells them exactly
  which files and how to exclude them.

### OD-07 — Per-finding severity vs GitHub's per-rule severity

- **Problem:** GitHub reads `security-severity` from the rule. nexvul's severity changes per finding (taxonomy
  §2 modifiers, e.g. production indicators raise NEX017 to critical). GitHub's badge will show the rule
  default.
- **Options:**
  1. Rule default in the badge; effective severity first in `message.text` and in
     `properties.nexvul.severity` (recommended).
  2. Emit severity-variant rules (`NEX017` and `NEX017/critical`): badge correct, but rule IDs fragment,
     alert history splits when severity changes, filters get confusing.
  3. Drop per-finding modifiers: simpler, loses the taxonomy's main precision lever.
- **Recommendation: 1**, revisit if GitHub adds per-result severity. Verification is contract ask CA-3.
- **What users will notice:** a GitHub alert badge saying "High" whose message starts "CRITICAL ·". Rule help
  explains this in one line.

### OD-08 — HTML report in v1
*Conflict between threat-model handoff D9 ("defer unless product needs it") and roadmap Phase 2 / competitor
research ("primary differentiator for adoption").*

- **Options:** ship in Phase 2 thin slice; ship in Phase 6 with integrations; defer past v1.
- **Recommendation: ship in the Phase 2 thin slice, with SR-13 (headless-browser XSS/CSP/no-network suite and
  the H13 hostile fixture) as a release blocker.** The report is the only surface a developer can hand to a
  non-developer, and the design keeps its attack surface small: static HTML, `textContent` only, `<details>`
  instead of JS for disclosure, no external assets.
- **If deferred:** README screenshot uses the terminal only; H-screens stay designed and parked.

### OD-10 — Brand and visual deviations from the existing report mock-up

Approve or reject each of DV-1…DV-12 in `design-system.md` §10. The material ones:

- **DV-2 no green**, **DV-3 remove "OWASP Coverage" tile**, **DV-7 replace the shield mark** — all three remove
  visual claims the product cannot back.
- **DV-8 rule IDs** — the mock-up's IDs conflict with the taxonomy; the mock-up should be regenerated before it
  is used in any README or announcement.
- **Recommendation:** approve all; regenerate `assets/report-preview.html` from these tokens once the report
  template exists (do not hand-edit the mock-up).

## Non-blocking

| ID | Decision | Options | Recommendation and reason |
|----|----------|---------|---------------------------|
| OD-09 | Action emits `::error file=…` annotations in addition to SARIF | yes / no | **No in v1.** Duplicates code-scanning annotations; workflow commands are an injection channel for hostile filenames (T-10); capped per step so floods drop real ones. Revisit for fork PRs only, with strict escaping. |
| OD-11 | Canonical GitHub owner and repository URL | — | Decide before the first release; T11, G03 and A09 print it. Reserve look-alike names at the same time (T-26). |
| OD-12 | `nexvul init` writes a commented `.nexvul.yml` | add / skip | **Defer (P2).** The README example (C01) is enough for v1; an init command is one more surface that writes into the repo. |
| OD-13 | Info-level inventory findings in SARIF | upload / not | **Do not upload.** Uncloseable alerts teach dismissal. Show them in the HTML report under a collapsed "Context: agent capabilities" section and in `--verbose`. |
| OD-14 | pre-commit blocks the commit when a staged file fails to parse (K05) | block / warn | **Block** (exit 3), user config can downgrade. The developer is holding the broken file right now. |
| OD-15 | Default `fail-on` | critical / high / medium | **high.** Matches the brief §14 example and the FP budget's strongest guarantees (DEC-0002). |
| OD-16 | Keep `--explain NEX001` on `scan` as well as `nexvul explain` | keep / drop | **Keep** (brief §8 lists both); T13 prints the short form inline and points to the command for the full text. |

## Decisions already made elsewhere that this design depends on

| Source | Item | Design dependency |
|---|---|---|
| Brief §2 | No telemetry, no network | `doctor` states it (U05); README hero says it (D01) |
| Brief §0, security-model | Clean ≠ secure | Fixed strings in `tokens.json → copy` |
| DEC-0002 (escalated) | FP budget; low confidence off by default | U01 status column; report filters (H08) |
| Threat-model D8 | Plugins deferred | `doctor` lists entry points as "not loaded" (U06) |

## Sign-off

| ID | Decision taken | By | Date |
|----|----------------|----|------|
| OD-01 | | | |
| OD-02 | | | |
| OD-03 | | | |
| OD-04 | | | |
| OD-05 | | | |
| OD-06 | | | |
| OD-07 | | | |
| OD-08 | | | |
| OD-10 | | | |
