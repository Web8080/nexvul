# nexvul — GitHub Code Scanning and the GitHub Action

> Status: **Proposed design** (Phase 0). Nothing here is implemented. Sample data only.
> Owner: Design (Dave). Date: 2026-10-08. Screen IDs `G01–G05`, `A01–A09` from
> [`screen-inventory.md`](screen-inventory.md).
> Inputs: `docs/research/tooling/sarif.md`, `docs/research/tooling/github-actions-and-precommit.md`,
> threat model T-10, T-12, T-17, T-19, T-20.

## 1. Principles for every GitHub surface

1. **GitHub renders Markdown; scanned code is hostile.** Anything GitHub renders as Markdown (`help.markdown`,
   the job summary) contains only nexvul-authored text, plus repo-derived text that has been sanitised and
   placed inside an escaped inline code span (§5.4). Repo-derived text never becomes link text, a URL, an
   image, a heading or HTML. (T-12, SR-12)
2. **Results use `message.text` only.** No `message.markdown`, ever.
3. **Partial status must be visible without trusting GitHub to show it.** GitHub's rendering of SARIF
   `invocations` and notifications is not something nexvul controls. The partial status therefore travels by
   three independent routes: the job's exit code (fails the check), the job summary (first line), and the SARIF
   run properties (for tools and audits). *Why three:* any one can be lost — `continue-on-error`, a collapsed
   summary, a UI that ignores notifications.
4. **One text, three renderings.** A rule's help is written once (`docs/rules/NEX0nn.md`) and rendered to
   `nexvul explain` (U03), SARIF `help.markdown`/`help.text` (G03) and the HTML report (H05). Section order is
   identical in all three so an engineer who learned one can read the others.

## 2. SARIF → GitHub mapping

| nexvul field | SARIF location | Where it appears in GitHub | Notes |
|---|---|---|---|
| Rule ID `NEX002` | `rules[].id`, `results[].ruleId` | Alert list "Rule" filter; alert detail header | Stable forever |
| Rule title | `rules[].shortDescription.text` | Alert title in list and detail | Built-in text only |
| Rule summary | `rules[].fullDescription.text` | Rule help header | Built-in |
| Rule help | `rules[].help.text` + `help.markdown` | "Show more" rule help panel (G03) | Built-in only; §4 layout |
| Default severity | `rules[].properties.security-severity` + `tags: ["security"]` | Severity badge & filter | Values §3 |
| ASI mapping | `rules[].properties.tags`: `security`, `external/owasp/asi06`, `external/cwe/cwe-20` | Tag chips on the rule | ≤ 20 tags, 10 shown |
| Confidence | `rules[].properties.precision` (`high`/`medium`/`low`) and `results[].properties.nexvul.confidence` | Rule metadata (display not guaranteed) + message text | Message text carries it regardless (§2.1) |
| Message | `results[].message.text` | Alert detail body (G02) | Template §2.1 |
| Location | `physicalLocation.artifactLocation.uri` (repo-relative, `uriBaseId: %SRCROOT%`), `region` | Highlighted code | No `..`, no scheme (T-12) |
| Flow | `results[].codeFlows[].threadFlows[].locations[]` | "Show paths" (G02) | Each step has `location.message.text` = step role |
| Snippet | `region.snippet.text` | Code preview | Sanitised, ≤ 3 lines, secrets redacted |
| Fingerprint | `partialFingerprints.primaryLocationLineHash` | Alert de-duplication across pushes | Computed by nexvul |
| Suppression | `results[].suppressions[] = {kind: "inSource", justification}` | Suppressed/closed state (G04) | GitHub display unverified (contract ask CA-3) |
| Completeness | `invocations[0].executionSuccessful`, `toolExecutionNotifications[]`, `toolConfigurationNotifications[]`, `runs[].properties.nexvul.completeness` | Tool status (G05) where GitHub shows it | Never the only route (§1.3) |
| Category | `runAutomationDetails.id = "nexvul/"` + Action `category: nexvul` | Separates nexvul from other tools | Fixed default |

### 2.1 `message.text` template (G02)

```
{SEVERITY} · {one specific sentence}. {qualifier} Confidence: {confidence}. Steps: {n} (Show paths).
```

Examples (sample data):

- `HIGH · Content returned by requests.get() reaches vector_store.add_documents() without an identified
  validation or trust-boundary check. Confidence: high. Steps: 4 (Show paths).`
- `CRITICAL · Tool refund_order calls stripe.Refund.create() with an amount chosen by the model. No approval
  step was found on the path in the scanned code; controls outside this repository are not visible to nexvul.
  Confidence: medium. Steps: 3 (Show paths).`
- `HIGH · MCP server "search" is reached over http:// at a non-loopback host with no authentication
  configured. Confidence: high.`

**Rules for the template**

- Leads with nexvul's **effective** severity for this result (after modifiers), because GitHub's badge shows the
  rule's default (see §3 and OD-07). *Why in text:* the triager must not see "High" in the badge and miss that
  this instance is Critical.
- API names and identifiers from the scanned code are inserted only through named placeholders, sanitised
  (controls stripped, ≤ 80 chars each, `…` + hash suffix when truncated). GitHub may auto-link URLs in
  plain text; placeholders therefore never carry URLs — a URL literal from code is rendered as
  `<url literal, 42 chars>` in the message and kept in `snippet.text` only.
- Control-absence findings always include the qualifier "in the scanned code; controls outside this
  repository are not visible to nexvul" (taxonomy §1).
- Maximum 400 characters. The flow lives in `codeFlows`, not in the message.

### 2.2 Code flow steps ("Show paths")

Each `threadFlowLocation.location.message.text` is one of: `source: {what}`, `step`, `sanitiser not recognised`,
`sink: {what}`. Example for NEX002: `source: HTTP response body` → `step` → `step` → `sink: vector store write`.
*Why role words, not code:* the code is already shown at the location; the message tells the reader what role
nexvul assigned to it, which is the thing they need to dispute if it is wrong.

## 3. Severity mapping

| nexvul severity | `security-severity` (rule default) | GitHub badge | Result `level` |
|---|---|---|---|
| critical | `9.5` | Critical | `error` |
| high | `8.0` | High | `error` |
| medium | `5.5` | Medium | `warning` |
| low | `3.0` | Low | `note` |
| info | not emitted to SARIF | — | — |

*Why info is not uploaded:* inventory facts ("agent has a shell tool") are context, not alerts; uploading them
creates alerts nobody can close except by dismissal, which trains people to dismiss.

**Known gap (OD-07, blocking for G01):** GitHub takes `security-severity` from the **rule**, but nexvul's
severity varies per result (taxonomy §2 modifiers ±1). A NEX017 finding with a production indicator is Critical
in nexvul and High in GitHub's badge. Options in `open-decisions.md`. Recommendation: rule-level default in the
badge, effective severity first in `message.text`, and `results[].properties.nexvul.severity`; revisit if GitHub
adds per-result severity.

## 4. Rule help layout — `help.markdown` (G03)

Same sections, same order as `nexvul explain` (U03). Written by maintainers, reviewed like code, never templated
with scanned content. Rule-help lint (J5-F2) allows links only to allowlisted hosts (owasp.org, genai.owasp.org,
cwe.mitre.org, framework documentation domains, the nexvul repository).

Rendered example for NEX002 (exact Markdown that ships in the SARIF):

```markdown
**External content indexed into a vector store** · ASI06 Memory & Context Poisoning

A finding means nexvul identified a risky pattern. It does not prove the code is exploitable.

#### What nexvul looked for
Text fetched from outside the application (HTTP responses, web loaders, email, uploaded files) that reaches a
vector-store write (`add_documents`, `add_texts`, `upsert`, `from_documents`) with no validation or
trust-boundary step that nexvul recognises in between.

#### Why it matters
Documents in a vector store are retrieved later and placed in the model's context. Text an attacker controls on
a web page can carry instructions that the agent follows on a future, unrelated request.

#### How to fix
1. Allowlist the sources you index.
2. Record provenance (`source`, `trust`) on every stored document.
3. Keep retrieved text in user or tool messages with delimiters, never in system instructions.

| Flagged | Not flagged |
|---|---|
| `vector_store.add_documents([Document(page_content=requests.get(url).text)])` | source checked against `ALLOWED_SOURCES` and provenance recorded before `add_documents` |

#### What this rule does not detect
- Poisoned documents already in the corpus.
- Poisoning of embeddings or the model.
- Ingestion code outside this repository.
- Validation helpers nexvul does not recognise are treated as absent, which can cause a false positive.

#### Severity and confidence
Default severity **high**. Confidence **high** when the flow is inside one function, **medium** across files.
The alert message states this result's own severity and confidence.

#### Triage
- Snippets and identifiers in this alert come from the scanned repository. Treat them as untrusted text.
- Reproduce locally: `nexvul explain NEX002` and `nexvul scan --verbose <path>`.
- False positive? Report it with the rule's FP template so the rule improves for everyone:
  https://github.com/<owner>/nexvul/issues/new?template=false-positive.yml

#### Suppressing this finding
Add a comment on the flagged line or the line above, naming the rule and the reason:
`# nexvul: ignore[NEX002] -- <why this source is trusted>`
Suppressed findings stay visible as suppressed. In CI the reason is required.

#### References
- [OWASP Top 10 for Agentic Applications 2026 — ASI06](https://genai.owasp.org/)
- [nexvul rule NEX002](https://github.com/<owner>/nexvul/blob/main/docs/rules/NEX002.md)
```

`help.text` is the same content with Markdown removed (headings as uppercase lines, table as two labelled
lines). `<owner>` is fixed by OD-11.

## 5. GitHub Action

### 5.1 Inputs and outputs (design contract; final names with DevSecOps)

| Input | Default | Notes |
|---|---|---|
| `path` | `.` | Scan root, repo-relative |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `never` |
| `config` | *(base-ref `.nexvul.yml`)* | Explicit trusted config path; overrides base-ref lookup |
| `upload-sarif` | `true` | Uploads with `category: nexvul` in a separate step that holds the token |
| `category` | `nexvul` | For multiple scans in one workflow |
| `require-justification` | `true` | Inline suppressions without a reason stay active |
| `fail-on-partial` | `true` | Only `false` via this input (trusted), never via repo config |
| `allow-untrusted-checkout` | `false` | Needed to scan PR head under `pull_request_target`/`workflow_run`; never in examples |
| `html-report` | `false` | When `true`, writes `nexvul-report.html` as a workflow artifact |

| Output | Example |
|---|---|
| `exit-code` | `3` |
| `status` | `partial` |
| `findings-at-or-above-threshold` | `2` |
| `sarif-file` | `nexvul.sarif` |

### 5.2 A05 — Job conclusion

The job's pass/fail is the exit code (screen-inventory §9). The scan step's failure message (shown as the
step's error annotation on the run page) is one trusted line:

| Exit | Annotation title (trusted string) |
|---|---|
| 1 | `nexvul: 3 findings at or above high` |
| 3 | `nexvul: PARTIAL SCAN — 4 of 312 files not analysed` |
| 2 | `nexvul: configuration error (see job summary)` |
| 4 | `nexvul: internal error (see job summary)` |

GitHub's own "Code scanning results / nexvul" check (created from the uploaded SARIF) behaves according to the
repository's code-scanning protection settings, which nexvul does not control. The README tells users to
require **the nexvul job**, because only the job also fails on partial scans.

### 5.3 A04 — PR annotations

- Annotations on "Files changed" come from code scanning (SARIF upload on `pull_request`). nexvul does **not**
  also emit `::error file=…` workflow commands in v1. *Why:* (1) duplicates every annotation; (2) workflow
  commands are a line-oriented channel where an unescaped hostile filename can forge commands (T-10);
  (3) GitHub caps workflow-command annotations per step, so a flood would drop the important ones silently.
  Decision OD-09.
- Fork PRs cannot upload SARIF with the default read-only token; annotations then do not appear. A07 says so
  and the job summary carries the findings instead.

### 5.4 Job summary safety rules (all of A01–A09)

1. Built from a fixed template; only counts, rule IDs, rule titles (built-in), severities and sanitised
   paths/justifications are inserted.
2. Repo-derived text is: control/bidi/invisible characters escaped (SR-10); newlines removed; truncated
   (paths 120, justifications 120, + `…`); then wrapped in an inline code span whose backtick fence is one longer
   than the longest backtick run inside it, with a space padding when the text starts or ends with a backtick.
   Inside a code span Markdown links, images, emphasis and HTML do not render.
3. Pipe characters in table cells are escaped as `\|` **outside** code spans; inside code spans paths containing
   `|` are rendered with `¦` substituted and noted. *Why:* GitHub's table parser splits on `|` even inside code.
4. Never more than 50 finding rows; then "and N more — see Security → Code scanning or the SARIF artifact".
   Summary size stays well under GitHub's per-step summary limit.
5. No HTML tags in the summary template (no `<details>`), so the template has no HTML surface to get wrong.

### 5.5 A01 — Job summary: findings at/above threshold (exit 1)

Rendered Markdown (sample data):

```markdown
## nexvul — 3 findings at or above `high`

**Scan complete.** 312 of 312 files analysed · 25 of 25 rules · fail-on `high` · exit code 1

| Severity | Count |
|---|---|
| ████ Critical | 1 |
| ███░ High | 2 |
| ██░░ Medium | 1 |
| █░░░ Low | 1 |
| Suppressed | 1 |

### Findings at or above `high`

| Severity | Rule | Location | Title |
|---|---|---|---|
| ████ Critical | NEX018 | `agent/billing.py:58` | Financial action without human oversight |
| ███░ High | NEX002 | `agent/ingest.py:42` | External content indexed into a vector store |
| ███░ High | NEX007 | `mcp.json:12` | MCP connection without authentication or over cleartext |

Evidence, flow and fixes: **Security → Code scanning**, filter `tool:nexvul`. Learn a rule locally:
`nexvul explain NEX018`.

### Suppressions added in this pull request (1)

| Rule | Location | Justification |
|---|---|---|
| NEX006 | `agent/server.py:41` | `auth enforced by the API gateway (infra/gateway.tf, route /agents/*)` |

### Configuration

Effective config: `.nexvul.yml` at base `3f2c1a9`. Protections weakened by repository configuration: none.

<sub>nexvul 0.1.0 · rules sha256:9c1e… · A clean nexvul result does not prove that an application is secure.</sub>
```

*Why the first heading is the count at/above threshold:* it is the reason the job failed. The total count is
in the table below.

### 5.6 A02 — Job summary: complete, nothing at/above threshold (exit 0)

```markdown
## nexvul — no findings at or above `high`

**Scan complete.** 312 of 312 files analysed · 25 of 25 rules · frameworks: LangGraph, MCP · exit code 0

No findings at or above `high` from enabled rules. 2 lower-severity findings (1 medium, 1 low) are in
Security → Code scanning.

This does not prove the application is secure. nexvul checks specific code patterns in the files above; it does
not observe runtime behaviour, deployed configuration or model behaviour.

<sub>nexvul 0.1.0 · rules sha256:9c1e… · Suppressions: 0 · Weakened protections: none</sub>
```

No tick, no green, no "passed" in nexvul's own text. (GitHub's job icon will be green; nexvul's words are what
we control.)

### 5.7 A03 — Job summary: partial or failed (exit 3)

```markdown
## nexvul — PARTIAL SCAN: 4 of 312 files not analysed

> **This result is not a clean bill of health.** Code in the files below was not checked. The job fails until
> the scan is complete or trusted configuration excludes these files.

| Reason | Files | Examples |
|---|---|---|
| parse error | 2 | `agent/legacy.py`, `tools/gen_api.py` |
| over size limit (1 MB) | 1 | `data/fixtures.py` |
| parser timeout (30 s) | 1 | `agent/huge_graph.py` |

**Findings in analysed files:** 1 critical, 2 high, 1 medium (3 at or above `high`) — Security → Code scanning.

**What to do:** fix the parse errors, or add generated files to `exclude` in `.nexvul.yml` on the default branch
(exclusions are counted in every report). Do not add `continue-on-error`; it hides partial scans.

<sub>nexvul 0.1.0 · exit code 3 (scan incomplete) · rules sha256:9c1e…</sub>
```

For `SCAN FAILED` the heading reads `## nexvul — SCAN FAILED: <trusted cause>` and the findings line is omitted.

### 5.8 A06 — Refusal under `pull_request_target` / `workflow_run`

Job summary and step error:

```markdown
## nexvul — not run: untrusted checkout under `pull_request_target`

This workflow runs with your repository's secrets and a write-capable token, and it checked out code from the
pull request. Scanning that code here would expose those credentials to the pull request's author if anything
in the toolchain were compromised.

Use `on: pull_request` for scanning contributions (see the reference workflow in the nexvul README).
If you have reviewed this risk, set `allow-untrusted-checkout: true` on the nexvul step.

<sub>exit code 2 · nothing was scanned</sub>
```

### 5.9 A07 — SARIF upload failure

| Cause | Summary line (trusted) |
|---|---|
| Missing permission | `SARIF upload failed: the job needs permissions: security-events: write.` |
| Fork pull request | `SARIF upload is not available for pull requests from forks with the default token. Findings are listed in this summary and in the nexvul.sarif artifact.` |
| Duplicate category | `SARIF upload failed: another upload in this workflow already uses category "nexvul". Set a distinct category input.` |
| Size / limits | `SARIF upload rejected by GitHub. nexvul kept the file within documented limits; see the step log for GitHub's response.` |

In every case except fork PRs the job fails. For fork PRs the job conclusion still follows the scan's exit code,
and A01/A03 content is written in full so the reviewer has the findings.

### 5.10 A08 / A09 — Input/config error, internal error

```markdown
## nexvul — configuration error

`fail-on: hihg` is not a valid value. Use one of: critical, high, medium, low, never.

<sub>exit code 2 · nothing was scanned</sub>
```

```markdown
## nexvul — stopped unexpectedly (internal error)

This is a bug in nexvul, not in your code. No result was produced and no SARIF was uploaded.
Report it with the step log: https://github.com/<owner>/nexvul/issues/new?template=bug.yml

<sub>exit code 4</sub>
```

## 6. Contract asks (for the architect / DevSecOps)

| ID | Ask | Screens |
|---|---|---|
| CA-1 | Per-result effective severity in `results[].properties.nexvul.severity`; rule default in `security-severity` | G01, G02 |
| CA-2 | Each `threadFlowLocation` carries a role (`source`/`step`/`sanitiser-not-recognised`/`sink`) | G02, H05, T04 |
| CA-3 | Test repository to verify how GitHub renders `suppressions[]`, `toolExecutionNotifications`, `precision`, and URL auto-linking in `message.text` before v1 | G04, G05 |
| CA-4 | The scan step exposes status and counts as outputs without the token; upload is a separate step | A01–A07 |
| CA-5 | A "suppressions introduced by this change" list (needs base vs head comparison of suppression comments) | A01, T17, H06 |
| CA-6 | A single sanitiser API with three render targets: terminal `Text`, HTML text node, Markdown code span | all |
| CA-7 | Stable `primaryLocationLineHash` algorithm documented, with a regression test across whitespace-only edits | G01 |
