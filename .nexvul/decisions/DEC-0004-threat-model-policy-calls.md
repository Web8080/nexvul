# DEC-0004: Threat-model policy calls (config, suppressions, partial scans, plugins)

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("make the call") |
| Proposed by | 02 Security Gatekeeper (docs/threat-model.md; handoffs/threat-model.md D1-D10) |
| Date decided | 2026-10-08 |
| Links | docs/threat-model.md; docs/architecture.md |

Principle behind all four: a scanned repository is hostile, so nothing inside it may weaken the scan, and a
scan that was incomplete must never look clean.

## 1. Repo-local config in CI
**Decision:** a `.nexvul.yml` from the code under scan may only make the scan **stricter** (enable more rules,
lower the `fail_on` threshold, add excludes of nothing). Any setting that loosens the scan (disable rules, raise
the threshold, add excludes, relax limits) is honoured only when it comes from the **base branch** or from
trusted CI inputs, never from a PR head. Locally, developers' own config applies in full.
**Why:** a malicious PR could otherwise disable the rules that would catch it (suppression attack, threat model).
**Cost:** contributors must change loosening config in a separate, reviewed PR to the base branch.

## 2. Inline suppressions
**Decision:** in CI, an inline suppression must carry a written justification and the rule ID (`# nexvul: ignore
NEX001 -- reason`). A bare ignore is rejected as a config error in CI and allowed with a warning locally.
Suppressions added by a PR are listed in the report and in the job summary, and suppressed findings remain in
JSON/SARIF marked as suppressed.
**Why:** an attacker or a hurried developer can silence a finding with one comment; this keeps it visible and reviewable.

## 3. Partial scans
**Decision:** a scan that skipped, timed out on, or failed to parse any file, or hit a resource limit, is
reported as **partial**, uses a distinct non-zero exit code, and **fails CI by default**. `--allow-partial`
downgrades this to a warning and is itself shown in the completeness block. A partial scan is never rendered as
"clean".
**Why:** otherwise an attacker can hide a file behind a parse bomb and get a green check.

## 4. Rule plugins
**Decision:** built-in rules only until after 1.0. No auto-loading of rule plugins from installed packages.
A safe plugin model (explicit allow-list, no code execution inside the scanner process) is a post-1.0 design item.
**Why:** auto-loaded plugins give any co-installed package code execution inside nexvul.

## Reversibility
Items 1-3 can be relaxed later by a new decision record. Item 4 is reversible at the cost of a plugin design.
