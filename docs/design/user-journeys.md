# nexvul — User Journeys

> Status: **Proposed design** (Phase 0). Nothing here is implemented.
> Owner: Design (Dave). Date: 2026-10-08.
> Companion files: [`screen-inventory.md`](screen-inventory.md) (every ID referenced below),
> [`terminal-mockups.md`](terminal-mockups.md), [`github-and-action.md`](github-and-action.md),
> [`design-system.md`](design-system.md), [`open-decisions.md`](open-decisions.md).
> SVG renderings of each flow: [`flows/`](flows/) (generated from `_build/flows.py`; the text below is the
> source of truth if the two ever disagree).

## 0. The one rule every journey obeys

At every point where a person could conclude "my agent is fine", the surface in front of them shows **what was
and was not analysed**. A journey that ends on a zero-finding result ends on a statement of scope, never on a
green tick. This is why the success path of every journey below terminates in a *completeness* screen, and why
the most important failure branches are the quiet ones: partial scans, rules that had nothing to attach to,
and suppressions added by the same person whose code was flagged.

## 1. Who the journeys are for

| ID | Person | Where they meet nexvul | What they need in the first 60 seconds | What would make them stop trusting it |
|----|--------|------------------------|----------------------------------------|----------------------------------------|
| U-DEV | AI app developer | Their terminal, on their laptop | One install line, one scan line, a finding they can understand without reading docs | A finding that is plainly wrong; a "clean" result on a repo they know is risky |
| U-SEC | AppSec engineer | GitHub code scanning (Security tab, PR annotations) | Enough evidence in the alert to decide true/false positive without cloning the repo | Alerts that say "dangerous" without saying why; duplicate alerts after every push |
| U-PLAT | Platform / CI engineer | `.github/workflows/*.yml`, job logs, job summary | A copy-paste workflow that fails the build for the right reasons and only those | A green check on a scan that silently skipped files; a red check they cannot explain |
| U-OSS | Open-source contributor | `CONTRIBUTING.md`, `nexvul rules`, rule templates, tests | A clear path from "I know an attack pattern" to a merged, tested rule | A process that rejects work without saying what evidence was missing |

## 2. Journey index

| # | Journey | Primary actor | Other actors | Surfaces touched | Flow file |
|---|---------|---------------|--------------|------------------|-----------|
| J1 | First run on a local repo | U-DEV | — | D01, D02, T01–T08, T18, T19, U03, H01–H07 | `flows/J1-first-run.svg` |
| J2 | Triage an alert in GitHub code scanning | U-SEC | U-DEV | G01–G05, A04, U03 | `flows/J2-triage.svg` |
| J3 | Suppress a false positive with a justification | U-DEV | U-SEC (reviewer) | C03–C06, T17, G04, A01 | `flows/J3-suppress.svg` |
| J4 | Gate CI with `fail-on` | U-PLAT | U-DEV, GitHub | D06, C01, A01–A09, T15, T23 | `flows/J4-ci-gating.svg` |
| J5 | Contribute a rule | U-OSS | Maintainer, CI | D05, D04, U01, U03, U06 | `flows/J5-contribute-rule.svg` |
| J6 | Commit with the pre-commit hook (supporting) | U-DEV | — | K01–K05 | (covered inside J1/J3 text) |

Notation used in the text flows: `[ID]` is a screen from the inventory; `◇` is a decision; `✕` is a failure
branch; `→` is the next step. Exit codes are the contract in `screen-inventory.md` §9.

---

## J1. First run on a local repo (U-DEV)

**Goal:** the developer installs nexvul, scans their agent project, and understands one finding well enough to
fix it, without reading documentation first.

**Entry points:** README above the fold [D01]; a colleague's PR comment linking the README; PyPI page.

### J1 happy path

1. Reads the README hero [D01]: one-line value statement, install line, scan line, a real terminal screenshot,
   and the sentence *"A clean result does not prove your application is secure."* within the first screen.
2. Runs `pipx install nexvul` (recommended) or `pip install nexvul` in a dedicated venv [D02].
   *Why pipx first:* installing into the scanned project's own environment lets that project's dependencies
   load code into nexvul (threat model T-25). The README says so in one line, not a paragraph.
3. Runs `nexvul scan .` from the project root.
4. Sees progress [T01] on stderr: discovery count, then a single progress line. No per-file spam.
5. ◇ Did discovery find any analysable files?
   - ✕ No → [T18] *Nothing to analyse.* Exit 3. Lists what was found (e.g. "12 files, none Python, TypeScript,
     JavaScript or a recognised agent config") and the two most likely causes (wrong directory; language not
     yet supported). Never prints "No findings".
6. ◇ Were any agent frameworks recognised?
   - ✕ None → scan continues, but the header shows `Frameworks: none recognised` and the completeness block
     carries the note from [T19]: framework-specific rules had nothing to attach to, so a zero-finding result
     here means even less than usual. *Why:* this is the most likely silent false-clean for a first-time user
     whose framework is not yet supported.
7. ◇ Did every discovered file parse and analyse inside limits?
   - ✕ No → status `PARTIAL` [T05 / T06]. The partial banner is the **last** thing printed, from trusted
     strings, and cannot be silenced by `--quiet`. Exit 3.
8. Findings print grouped by severity [T04], highest first. Each finding shows: severity label + meter, rule ID,
   title, ASI tag, `file:line`, one specific sentence, and the flow as numbered steps.
9. ◇ Any findings?
   - No, and status `COMPLETE` → [T02] *"No findings from enabled rules. This does not prove the application is
     secure."* followed by what was checked (rules run, files analysed, frameworks recognised). Exit 0.
10. Picks the top finding and runs `nexvul explain NEX002` [U03] (the command is printed under every finding
    group, so it is discoverable without docs). Sees source → flow → sink → why it matters → how to fix →
    what this rule does not detect.
11. Optionally runs `nexvul scan . --format html --output nexvul-report.html` [H01] to share with a colleague.
    The report opens offline [H01] with the same completeness block at the **top** [H07].
12. Fixes the code, re-runs, and sees the finding gone and the summary updated [T03 or T02].

### J1 failure branches (each must be designed, not left to the stack trace)

| Branch | Trigger | Screen | Exit | What the developer sees and does next |
|--------|---------|--------|------|---------------------------------------|
| J1-F1 | Python < 3.12 | install-time pip error (not ours); then [U05] in `doctor` | — | README states the requirement next to the install line so the pip error is not a surprise |
| J1-F2 | Path argument does not exist / is outside the scan root | [T10] | 2 | "Path not found: `./agnet`. Did you mean `./agent`?" Nothing scanned |
| J1-F3 | Broken `.nexvul.yml` | [T09] | 2 | Exact key, line, column, and the accepted values. No partial scan is run with a half-read config |
| J1-F4 | Some files failed to parse | [T08] summary, [T12] detail | 3 | Count by reason in the default view; file list with `--verbose`; "Why this matters: code in these files was not checked" |
| J1-F5 | Global time limit hit | [T25] | 3 | Which phase was cut short; how to raise the limit (trusted config/CLI only) |
| J1-F6 | Ctrl-C | [T20] | 130 | "Scan interrupted. No result was produced." Never prints a partial findings list that could be mistaken for a full one |
| J1-F7 | nexvul itself crashes | [T11] | 4 | One-line cause, the bug-report URL, and `nexvul doctor` hint. No source content in the message; nothing is uploaded |
| J1-F8 | Output file already exists and is not a nexvul report | [T22] | 2 | Refuses; suggests `--force` |
| J1-F9 | Developer installed nexvul into the project venv | [U06] via `nexvul doctor` | — | Doctor warns: "nexvul shares an environment with the project it may scan." Explains why in one sentence |

### J1 success criteria (for usability testing)

- A developer new to nexvul reaches step 10 in under 5 minutes with no documentation beyond the README hero.
- Asked "is your agent secure now?" after a zero-finding run, the developer answers some form of "it found
  nothing in what it checked" rather than "yes". This is the design's real acceptance test.

---

## J2. Triage an alert in GitHub code scanning (U-SEC)

**Goal:** the AppSec engineer decides, from GitHub alone, whether an alert is a true positive, a false positive,
or needs the developer's input; and records that decision where GitHub and nexvul can both see it.

**Entry points:** Security tab → Code scanning → filter `tool:nexvul` [G01]; PR "Files changed" annotation
[A04]; notification email from GitHub.

### J2 happy path

1. Opens the alert list [G01], filters by tool `nexvul` and severity. Severity in GitHub comes from the rule's
   `security-severity`; nexvul's own severity and confidence also appear in the alert title line text (see
   [G02] and decision OD-07 on per-finding severity).
2. Opens an alert [G02]. Reads, in this order:
   - the **result message** (`message.text`): one specific sentence naming the source API, sink API and
     function, ending with `Confidence: high`;
   - the **highlighted location**;
   - **Show paths** (SARIF `codeFlows`): numbered steps from source to sink, each with file:line.
3. Expands the **rule help** [G03] (rendered from built-in `help.markdown`, never from scanned content):
   why it matters, how to fix, what the rule does not detect, OWASP mapping, how to suppress with justification.
4. ◇ Is the flow real?
   - Yes → assigns to the developer or opens an issue from the alert. Done.
   - It is real but already mitigated by a control nexvul cannot see (gateway auth, sandbox) → J3 (suppress
     with justification in code, so the reasoning lives next to the code and travels with it).
   - No, nexvul misread the code → GitHub "Dismiss alert → False positive" with a comment, **and** the rule help
     links to the FP report template so the rule can improve. *Why both:* a GitHub dismissal is invisible to
     nexvul and to every other repository; the FP report is how precision improves.
   - Cannot tell from GitHub → asks the developer to run `nexvul explain NEX0xx` and `nexvul scan --verbose`
     locally [U03, T12]; the alert's help text includes that exact command.
5. ◇ Is the run that produced this alert complete?
   - The engineer checks the tool status [G05]. If the run was partial, GitHub shows a nexvul tool notification
     ("N files not analysed"). *Why this step exists:* an alert list that looks short may be short because the
     scan was partial. The job summary [A03] says the same thing in larger type.

### J2 failure branches

| Branch | Trigger | Screen | Design response |
|--------|---------|--------|-----------------|
| J2-F1 | Same finding reappears as a new alert after a refactor | [G01] | Stable `partialFingerprints` (line-hash over normalised context) so moved code keeps its alert; documented limit: a renamed function may still create a new alert |
| J2-F2 | Alert snippet contains attacker text (a malicious docstring, a URL) | [G02] | Snippet appears only in SARIF `region.snippet.text` / escaped `message.text`; never in Markdown. Rule help warns "Snippets come from the scanned repository; treat them as untrusted" |
| J2-F3 | Results truncated at GitHub's 5,000-shown limit or nexvul's own cap | [G05], [A03] | Run marked `executionSuccessful: false`, truncation listed in tool notifications and job summary; highest severities kept first |
| J2-F4 | SARIF upload rejected | [A07] | The job fails. Never `continue-on-error` in the reference workflow |
| J2-F5 | Alert dismissed in GitHub, but the code is unchanged and suppressed in code later | [G04] | SARIF `suppressions[]` shows as suppressed in GitHub; both records agree |

---

## J3. Suppress a false positive with a justification (U-DEV, reviewed by U-SEC)

**Goal:** the developer silences one specific finding at one specific location, with a reason a reviewer can
read, and the suppression stays visible everywhere.

**Design stance:** a suppression is a *claim made by the person whose code was flagged*. nexvul never hides it;
it counts it, shows it, and in CI shows separately the suppressions this pull request introduced.

### J3 happy path

1. Sees the finding [T04] and decides it is mitigated elsewhere.
2. Runs `nexvul explain NEX006` [U03]; the "Suppressing this finding" section shows the exact syntax with
   the rule ID pre-filled.
3. Adds, on the flagged line or the line above, a comment naming the rule and a justification [C03]:
   `# nexvul: ignore[NEX006] -- auth enforced by the API gateway (infra/gateway.tf, route /agents/*)`
4. Re-runs the scan. The finding moves from the findings list to the **Suppressed** block [T17]: rule, location,
   justification (escaped, truncated to 120 characters), and the count in the summary line.
5. Commits. The pre-commit hook [K01] passes; its last line still reports `1 suppressed`.
6. Opens a PR. In CI [A01], the job summary has a section **"Suppressions added in this pull request (1)"**
   listing rule, file:line and justification, so the reviewer sees the claim without hunting for it.
7. U-SEC reviews. In GitHub code scanning the alert shows as suppressed in source [G04].

### J3 failure branches

| Branch | Trigger | Screen | Exit (CI) | Response |
|--------|---------|--------|-----------|----------|
| J3-F1 | No justification, CI requires one (proposed default; OD-03) | [C04] | finding counts as **unsuppressed** | "Suppression for NEX006 at agent/server.py:41 has no justification. Add one after `--`. The finding is reported as active." |
| J3-F2 | Blanket suppression `# nexvul: ignore` with no rule ID | [C05] | finding active | "Suppressions must name a rule, e.g. `ignore[NEX006]`. This comment was ignored." |
| J3-F3 | Suppression contains bidi or invisible characters | [C05] | finding active + a separate warning | "This suppression contains hidden characters (U+202E) and was ignored." *Why:* Trojan Source pattern (T-17) |
| J3-F4 | Wrong rule ID in the comment | [C05] | finding active | "`ignore[NEX060]` names no rule. Did you mean NEX006?" |
| J3-F5 | Suppression no longer matches any finding (stale) | [T17] note | none | "1 suppression matched nothing (agent/old.py:12)." Keeps the codebase honest; never an error |
| J3-F6 | Developer instead disables the rule in `.nexvul.yml` in the same PR | [C06], [A01] | in CI the weakening is **not applied** from PR head (proposed; OD-01) | Job summary: "Protections weakened by repository configuration: rules.disabled NEX006 — not applied (config from pull request head)" |
| J3-F7 | Suppression inside a string literal that looks like a comment | — | finding active | Parsed from real comment tokens only; nothing to show unless `--verbose` |

---

## J4. Gate CI with `fail-on` (U-PLAT)

**Goal:** the platform engineer adds nexvul to CI so that pull requests fail when findings at or above a chosen
severity appear, *or when the scan could not be completed*, and pass otherwise, with a summary that explains
either outcome to the developer who reads it.

### J4 happy path

1. Copies the reference workflow from the README [D06]. It uses `on: pull_request`, job-level
   `permissions: {contents: read, security-events: write}`, `persist-credentials: false`, the Action pinned
   by commit SHA, and `fail-on: high`.
2. Optionally commits a `.nexvul.yml` [C01] on the default branch (`severity.fail_on`, `exclude` for generated
   code). Protects it with CODEOWNERS (the README says so next to the config example).
3. Opens a test PR. The Action runs:
   - detects CI mode [T23]; prints the effective config with where each key came from;
   - scans; writes SARIF; uploads it with a fixed `category: nexvul`;
   - writes the job summary [A01/A02/A03];
   - sets the job conclusion from the exit code [A05].
4. ◇ Outcome by exit code (contract in `screen-inventory.md` §9):
   - `0` → job passes; summary [A02] says *"No findings at or above `high` from enabled rules. Scan complete:
     214 of 214 files analysed. This does not prove the application is secure."*
   - `1` → job fails; summary [A01] leads with the count at/above threshold and links each finding to its
     code-scanning alert.
   - `3` → job fails; summary [A03] leads with the partial banner and the skip reasons table.
   - `2` → job fails; [A08] names the bad input or config key.
   - `4` → job fails; [A09] "nexvul stopped unexpectedly"; the upload step does not run with a half-written SARIF.
5. Turns on branch protection requiring the job.

### J4 failure branches

| Branch | Trigger | Screen | Response |
|--------|---------|--------|----------|
| J4-F1 | Workflow uses `pull_request_target` or `workflow_run` with PR-head checkout | [A06] | Action refuses and fails: names the event, the risk in one sentence, and the safe alternative. Override input `allow-untrusted-checkout: true` is documented but never in examples |
| J4-F2 | `fail-on` value invalid (`hihg`) | [A08] | Exit 2, "fail-on must be one of: critical, high, medium, low, never" |
| J4-F3 | PR edits `.nexvul.yml` to raise `fail_on` to `critical` | [A01] weakened block | Not applied from PR head (OD-01); listed under "Protections weakened by repository configuration" |
| J4-F4 | Repo has huge generated files → partial every run | [A03] | Summary suggests a trusted `exclude` on the default branch; the excluded count still appears in completeness (exclusion by trusted config does not make a scan partial) |
| J4-F5 | Engineer adds `continue-on-error: true` or `|| true` | — (docs) | Reference docs explain why this turns a partial scan into a green check. nexvul cannot prevent it; the job summary still shows PARTIAL |
| J4-F6 | SARIF upload lacks `security-events: write` | [A07] | Upload step fails; summary says which permission is missing |
| J4-F7 | Fork PR (read-only token, upload not permitted) | [A07] variant | Summary is still written; SARIF kept as an artifact; message explains GitHub's fork limitation |
| J4-F8 | Two uploads with the same category in one workflow | [A07] | Error names `category` as the cause |

---

## J5. Contribute a rule (U-OSS)

**Goal:** a contributor turns knowledge of an agent attack pattern into a rule that ships, without guessing what
evidence maintainers require.

**Design stance:** the rule lifecycle in the brief (§6) is long by design. The contributor's experience is made
tolerable by making each gate visible, ordered, and testable locally, not by shortening it.

### J5 happy path

1. Reads `CONTRIBUTING.md` → "Propose a rule" [D05]: the lifecycle as a numbered list with what evidence each
   gate needs, and the rule-proposal template (Threat, OWASP mapping, Detection strategy, Positive examples,
   Negative examples, False positives, False negatives, Performance impact, References).
2. Runs `nexvul rules` [U01] and `nexvul rules --asi ASI07` [U02] to check the pattern is not already covered;
   reads `nexvul explain` for the nearest rule [U03], especially "What this rule does not detect".
3. Opens a **rule proposal** issue from the template. No code yet.
4. ◇ Maintainer triage: accepted for design / needs evidence / out of scope (e.g. not statically detectable).
   - ✕ Out of scope → the closing comment names the reason category from the taxonomy (§5 exclusions) so the
     contributor learns the boundary.
5. A rule ID is allocated by a maintainer (`NEX0nn`; never reused) — contributors do not pick IDs.
6. Writes the rule plus `tests/{positive,negative,edge_cases,adversarial}/` and `docs/rules/NEX0nn.md` from
   the template [D04].
7. Runs locally: rule tests, `nexvul scan benchmarks/safe --rules NEX0nn` (expects zero high-confidence
   findings), and the FP report command.
8. Opens the PR. CI posts the per-rule precision/recall table against the benchmark corpus.
9. ◇ Meets the FP budget (DEC-0002, pending)? Yes → review gates → merged as `experimental` (off by default)
   → promoted to default after a release cycle. No → CI comment shows exactly which `safe/` cases fired.

### J5 failure branches

| Branch | Trigger | Response |
|--------|---------|----------|
| J5-F1 | Rule interpolates scanned content into its message template unsafely | Rule-metadata lint fails: "message templates may use only named, escaped placeholders" |
| J5-F2 | `help` text contains a link to a non-allowlisted host | Lint fails; built-in help may link only to OWASP, MITRE CWE, framework docs, and nexvul docs |
| J5-F3 | Rule message uses a banned phrase ("vulnerable", "insecure", "safe") | Copy lint fails with the replacement from `design-system.md` §8 |
| J5-F4 | Contributor's rule duplicates an existing rule's sink | Dedupe check comment names the overlapping rule |

---

## J6. Pre-commit hook (supporting journey, U-DEV)

1. Adds the hook (rev pinned by SHA) to `.pre-commit-config.yaml` [D06 snippet].
2. On commit, the hook scans staged files only [K01/K02]. Cross-file analysis is off in this mode, and the hook
   says so in its last line, every time: *"Staged-file scan: cross-file flows not checked. Run `nexvul scan .`
   for a full scan."* [K03]
3. No relevant files staged → [K04] one line, exit 0, nothing else.
4. Findings at/above threshold → [K02] compact list, exit 1, commit blocked; the hint shows `git commit
   --no-verify` is the user's choice and that CI will still scan.

---

## 7. Coverage check: every node mapped to a screen

Every step and branch above references a screen ID. Nodes that had no screen in the existing materials and
were added by this design (the holes):

| Hole | Added as | Why it matters |
|------|----------|----------------|
| Scanning a directory with nothing nexvul can analyse | T18 | Otherwise prints "No findings" for the wrong directory — a false clean on day one |
| Files analysed but no framework recognised | T19 | Framework rules silently attach to nothing |
| Ctrl-C mid-scan | T20 | A half-printed findings list looks like a full one |
| Output file overwrite | T22 | Pre-commit argument-injection defence (T-14) needs a visible refusal |
| Global time limit | T25 | Limits are evasion primitives (T-22); must be visible |
| Stale suppression | T17 note | Suppressions rot; visible rot is cheap to fix |
| Suppressions added in this PR | A01 section | The reviewer otherwise never sees them |
| `pull_request_target` refusal | A06 | The most damaging CI misconfiguration for a scanner of untrusted code |
| Fork PR upload failure | A07 variant | Common, confusing, and not nexvul's fault — still nexvul's message |
| Per-finding severity vs per-rule `security-severity` | OD-07 | GitHub shows one severity per rule; nexvul's severity modifiers vary per finding |
| nexvul installed in the scanned project's environment | U06 | Supply-chain risk that only `doctor` can see |
| FP reporting loop from GitHub dismissal | J2 step 4 | Dismissals in GitHub never reach the rule author |

## 8. Out of scope for these journeys (and what users will notice)

- **No baseline / "new findings only" mode in v1.** Teams adopting nexvul on an existing repo will see every
  existing finding on the first PR. Workaround: `fail-on: critical` initially. Designed as C08 (P2).
- **No auto-fix.** Remediation is text and examples only.
- **No IDE integration.** Developers who live in an editor get findings only via terminal or the HTML report;
  `file:line` is printed in a form most editors' terminals make clickable.
- **No LLM-assisted triage.** Every verdict is deterministic (security-model G10).
