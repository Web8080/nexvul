# Handoff — Threat Model (Phase 0)

- **From:** Security Gatekeeper / Threat Modeller
- **To:** Principal Supervisor; cc Architecture, QA/Test, DevSecOps, Documentation, Release
- **Date:** 2026-10-08
- **Status:** Proposed — requires Supervisor review and the human decisions listed in §4.

## 1. Deliverables

| File | Content |
|------|---------|
| `docs/threat-model.md` | System description, DFD, assets, 7 trust boundaries, 7 adversaries, STRIDE per component, threats T-01..T-30 (+T-01b), mandatory scan-completeness spec (§7), security requirements SR-01..SR-30, findings against current architecture (§9), primary sources. |
| `docs/security-model.md` | User-facing guarantees (design targets), non-guarantees, privacy stance, config trust, safe CI usage, pre-commit usage. States that a clean result does not prove security. |
| `.nexvul/security/malicious-input-test-plan.md` | ~110 hostile fixtures (MF-01..MF-185) with behaviour and expected safe outcome, universal assertions, canary convention, exit criteria. |

Nothing is implemented. No code written. No commits.

## 2. Highest-priority threats

1. **False assurance** (T-15, T-16, T-17, T-20, T-21, T-22): repo-local config, `.gitignore`, inline
   suppressions, in-repo cache, limits and SARIF rejection can each turn a vulnerable PR into a green check.
   Countered by the completeness block (threat-model §7) and CI-mode config trust (SR-15).
2. **Code execution in CI** (T-01, T-01b, T-19, T-25): `python -m` from the repo dir (sys.path shadowing),
   auto-loaded entry-point plugins from co-installed packages, `pull_request_target`.
3. **Output injection** (T-10..T-13): Rich markup and ANSI/OSC in terminal, Markdown into GitHub, XSS in HTML.
4. **Supply chain** (T-26..T-28): mutable Action tags (CVE-2025-30066 precedent), native grammar wheels,
   release-pipeline compromise (Ultralytics precedent).

## 3. Required changes to `docs/architecture.md` (for Architecture agent; I did not edit it)

1. §8.1 — move cache out of the scanned repo to the user cache dir; HMAC + version/rule/config keying (SR-08).
   The in-repo `.nexvul/cache/` also collides with `.nexvul/` as this project's agent workspace.
2. §9.5 — replace `signal.alarm` regex timeouts with process-isolated time limits (SR-03, SR-09).
3. §8.3 — replace bare `multiprocessing.Pool` with a supervised worker model that attributes worker death to a
   file and records it (SR-03).
4. §6.3 — plugin entry points opt-in via allowlist only (SR-22).
5. §1 Discovery — tracked files scanned regardless of `.gitignore` (SR-16).
6. §9.1 — skips feed completeness and exit codes, not just warnings (SR-18).
7. Add an exit-code contract (SR-19) and the completeness schema to the finding schema (§7).

## 4. Decisions needing a human (brief §32.2 — security trade-offs)

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| D1 | **Honour repo-local `.nexvul.yml` in CI by default?** | (a) Honour everything (simplest; T-15 open). (b) In CI mode apply only *strengthening* settings from PR head; weakening settings only from base ref or explicit `config:` input. (c) Ignore repo config entirely in CI. | **(b)**. Keeps per-repo tuning working via the base branch while closing the PR-author bypass. Cost: Action must fetch base config; config changes take effect only after merge — document it. |
| D2 | **Require justification on inline suppressions?** | (a) Optional. (b) Required always. (c) Optional locally, required in CI mode (`--require-justification` default on in CI). | **(c)**. Low local friction; CI produces an audit trail. Also: always reject blanket/no-rule-ID suppressions, always emit suppressed findings as suppressed. |
| D3 | **Honour inline suppressions at all in CI for PR scans?** | (a) Yes. (b) Yes, but list those introduced by the diff. (c) No. | **(b)**. |
| D4 | **Partial scan in CI: fail or warn by default?** | (a) Fail (exit 3). (b) Warn, exit by findings only. | **(a)** fail by default, trusted config can downgrade to warn. Risk: noisy failures on repos with generated giant files; mitigated by trusted excludes. |
| D5 | **Respect `.gitignore` for tracked files?** | (a) Respect. (b) Scan tracked files regardless. | **(b)**. Needs a way to read the git index without executing `git` — either a small in-house index reader or a dependency (see D7). |
| D6 | **ReDoS engine** | (a) stdlib `re` with discipline + fuzz meta-test + process timeouts. (b) Add an RE2 binding (native dependency). | **(a)** for v1; revisit if rules need complex regex. |
| D7 | **New dependencies implied** (brief §32.4): `platformdirs` (cache dir), git-index reader, HTML template engine (e.g. Jinja2 with autoescape) or hand-rolled DOM builder, actionlint/zizmor (dev-only). | Accept / reject each. | Prefer stdlib or tiny vetted deps; dev-only tools are low risk. |
| D8 | **Plugins in v1 at all?** | (a) Ship allowlisted plugin support. (b) Defer plugins to post-1.0. | **(b)** — removes T-25 from v1 entirely. |
| D9 | **HTML report in v1?** | (a) Ship. (b) Defer. | Defer unless product needs it; it adds T-13 surface. If shipped, SR-13 is a release blocker. |
| D10 | **Exit-code contract** (0/1/2/3/4 proposed). | Accept / modify. | Accept; it is a public API once released. |

## 5. Hand-offs to other agents

- **QA/Test:** implement `.nexvul/security/malicious-input-test-plan.md` as `tests/security/`; canary + audit-hook
  harness + socket-blocking harness first, since every fixture depends on them. Curate MF-17 (AST-compiler crash
  input) from the CPython issue tracker per supported version; confirm which non-UTF-8 coding cookies CPython
  3.12+ accepts for MF-122.
- **DevSecOps / Release:** SR-21, SR-26, T-27 — Trusted Publishing, SHA-pinned actions, no
  `pull_request_target` in nexvul's own repo, hash-pinned lockfile, SBOM, PyPI name-squat reservation.
- **Documentation:** `SECURITY.md`; link-check the sources in threat-model §10 (only the GitHub SARIF page,
  the Python `ast` page and the PyPI Ultralytics post were fetched and verified during this task).
- **Reporting implementers:** a single untrusted-string sanitiser (SR-10) shared by all reporters; Rich `Text`
  only (SR-11); SARIF `markdown` fields only from built-in rule docs (SR-12).

## 6. Known gaps / limitations of this model

- Brief §20 does not exist in the master brief; §19 and §21 were applied.
- Evasion (T-18) residual risk is **high** by design; nexvul can only make some evasions visible.
- Native parsers (tree-sitter grammars, PyYAML C loader) remain a memory-safety surface; OS-level sandboxing
  (seccomp/landlock/sandbox-exec) is listed as future hardening, not a v1 requirement.
- GitHub's handling of SARIF `suppressions` and rendering of `message.text` links were not verified; re-check
  when the SARIF writer is built.
- Threat model must be revisited when: any network/LLM feature is proposed, plugins ship, the HTML report ships,
  or a new input format (archives, notebooks, Docker images) is added. Archives are **not** to be opened in v1;
  treat them as binary and count them as skipped.
