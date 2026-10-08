# nexvul — Security Model

> Status: **Proposed** (Phase 0). This document states the security properties nexvul is being built to
> provide. Nothing here is implemented yet; each property is backed by a numbered requirement in
> [`docs/threat-model.md`](threat-model.md) (SR-xx) and is only to be described as "provided" once its tests
> pass.

## The one thing to remember

**A clean nexvul result does not prove that an application is secure.**

nexvul is a static scanner for a subset of risks from the OWASP Top 10 for Agentic Applications. It looks for
specific risky code patterns. It deliberately favours precision over recall, so it will miss real problems. It
cannot observe runtime behaviour, deployed configuration, model behaviour, or code it was unable to analyse. Treat
"no findings" as "these rules found nothing in the files that were analysed", nothing more.

## What nexvul treats as hostile

Everything in the repository being scanned: source code, comments, docstrings, prompts, tool descriptions,
manifests, filenames, directory layout, symlinks, `.gitignore`, `.nexvul.yml`, inline suppression comments, and
anything committed under `.nexvul/`. nexvul is designed to be run against code you do not trust, including pull
requests from strangers.

## Guarantees (design targets)

| # | Guarantee | Requirement |
|---|-----------|-------------|
| G1 | **No execution of scanned code.** nexvul does not run, import, build or install the target project, its scripts, its tests or its tools. It parses files as text into syntax trees. | SR-01, SR-02 |
| G2 | **No network.** Scanning makes no network connections. There is no telemetry and no update check. Any future network feature will be opt-in and clearly labelled. | SR-23 |
| G3 | **Stays inside the repository.** nexvul does not follow symlinks by default and never reads files outside the directory you asked it to scan, nor inside `.git/`. | SR-06, SR-28 |
| G4 | **Writes only where you tell it.** Reports and the cache go to locations set by you (CLI flags, your user config, Action inputs), never by the scanned repository. The cache lives in your user cache directory, not in the repo. | SR-07, SR-08 |
| G5 | **Bounded resources.** Huge files, deeply nested code, file-count bombs and pathological inputs are bounded by limits; a file that crashes the parser cannot crash the scan. | SR-03, SR-04, SR-05, SR-09 |
| G6 | **Honest completeness.** Every output says whether the scan was complete. Skipped files, parser failures, exhausted limits, suppressions and weakened configuration are listed. A partial scan is never presented as clean, and in CI it fails with a distinct exit code. | SR-18, SR-19 |
| G7 | **Safe output.** Text taken from the scanned repo is escaped before it reaches your terminal, the GitHub code-scanning UI, or the HTML report, so it cannot inject terminal escape sequences, Markdown, links or scripts. | SR-10 – SR-13 |
| G8 | **Visible suppressions.** Suppressed findings are still reported as suppressed, with counts, so a suppression added in a pull request is visible. | SR-17 |
| G9 | **Auditable results.** Outputs record nexvul version, rule-pack hash, effective configuration and where each setting came from, and any plugins loaded. | SR-27 |
| G10 | **No AI in verdicts.** nexvul v1 contains no LLM. If an LLM feature is ever added it will be opt-in, cannot change findings, severities, suppressions or exit codes, and will never send source off your machine without your explicit approval. | SR-25 |

## Non-guarantees

nexvul does **not**:

- Prove the absence of vulnerabilities. A clean result does not prove security.
- Detect every instance of the risks it targets. Indirection, dynamic dispatch, code generation, obfuscation,
  `exec` of computed strings, cross-file flows beyond its analysis budget, unsupported frameworks and languages,
  and deliberately crafted evasions can all hide a real issue. Where nexvul notices that it could not analyse
  something, it says so; it cannot notice everything.
- Prove exploitability. A finding means a risky pattern was identified, not that an attack succeeds.
- Validate runtime configuration, deployed infrastructure, model behaviour, prompts as interpreted by a model,
  third-party MCP servers you connect to at runtime, or your dependencies' code (unless vendored into the scanned
  tree).
- Protect you if you install it into the same Python environment as the untrusted project and that project's
  dependencies are malicious. Install nexvul in its own environment (see below).
- Protect you from an unsafe CI workflow you wrote yourself (for example, running any tool on PR-head code under
  `pull_request_target` with secrets available).
- Make plugin rule packs safe. Plugins are ordinary Python code with full access to your environment; they are
  off by default and load only when you allowlist them.
- Guarantee that every code snippet in a report is free of secrets. Secret-shaped values are redacted
  heuristically; treat reports as potentially sensitive.

## Privacy stance

- Your source code never leaves your machine because of nexvul. Scanning is entirely local.
- No telemetry, analytics, crash reporting or update checks — not even opt-out ones.
- The HTML report is self-contained and loads nothing from the internet when opened.
- Reports contain code snippets and file paths from your repository. If you upload SARIF to GitHub or keep
  reports as CI artifacts, those snippets go wherever those systems put them. Absolute paths (which can reveal
  usernames) are not written to JSON or SARIF.
- The cache stores derived analysis data in your user cache directory with owner-only permissions. Delete it at
  any time; `--no-cache` disables it.

## Configuration trust

- **Your** settings (CLI flags, your user config file, GitHub Action inputs) are trusted.
- A repository's own `.nexvul.yml` is **not** fully trusted, because whoever writes a pull request can edit it.
  In CI mode, settings in the repository's config that would *weaken* the scan (disabling rules, excluding paths,
  raising the failure threshold, lowering limits) are only applied when the config comes from a trusted source
  (the base branch, or a path you pass explicitly). Settings that strengthen the scan are always applied. Every
  output lists any weakening that was applied. *(Exact defaults pending a product decision; see the threat-model
  handoff.)*
- Files tracked by git are scanned even if `.gitignore` matches them.
- Inline suppression comments must name a specific rule. Suppressed findings remain visible in every output.
  In CI you can disable inline suppressions or require a written justification.

Protect `.nexvul.yml` with CODEOWNERS so changes to it require review from your security owners.

## Safe CI usage

Recommended GitHub Actions setup (illustrative; the real Action is not yet published):

```yaml
on:
  pull_request:            # NOT pull_request_target
  push:
    branches: [main]

permissions: {}            # deny by default

jobs:
  nexvul:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed to upload SARIF
    steps:
      - uses: actions/checkout@<full-commit-sha>   # vX.Y.Z
        with:
          persist-credentials: false
      - uses: <owner>/nexvul@<full-commit-sha>     # vX.Y.Z — pin by SHA, not tag
        with:
          fail-on: high
```

Rules of thumb:

1. **Use `pull_request`, not `pull_request_target`,** to scan contributions. `pull_request_target` runs with
   your repository's secrets and a write-capable token; combining it with a checkout of the PR's code hands
   that power to the PR author. The nexvul Action will refuse to scan PR-head code under
   `pull_request_target` or `workflow_run` unless you explicitly override it.
2. **Pin actions by full commit SHA**, including nexvul's. Tags can be moved; this has happened to widely used
   actions (e.g. CVE-2025-30066).
3. **Grant the minimum token permissions.** The scan needs none; only the SARIF upload needs
   `security-events: write`.
4. **Set `persist-credentials: false`** on checkout so the token is not stored in `.git/config`.
5. **Install nexvul in an isolated environment** (the Action does this; locally use `pipx` or a dedicated venv).
   Do not `pip install` the scanned project's requirements into the environment nexvul runs in.
6. **Do not share nexvul's cache across trust levels** (e.g. via `actions/cache` restored into PR jobs from a
   privileged workflow). The Action disables the cache by default.
7. **Treat a partial scan as a failure.** Do not wrap nexvul in `|| true` or `continue-on-error`. Exit codes
   (proposed): `0` complete and below threshold · `1` findings at/above threshold · `2` usage or config error ·
   `3` scan incomplete · `4` internal error.
8. **Make sure the SARIF upload succeeds.** A rejected or truncated upload must fail the job; nexvul keeps
   output within GitHub's documented limits and reports any truncation.

## pre-commit usage

Pin the hook's `rev:` to a full commit SHA. The hook is configured so that staged filenames can never be
interpreted as command-line options.

## Reporting a vulnerability in nexvul

See `SECURITY.md` (to be written by the Documentation agent). Please report privately; do not open a public
issue for a vulnerability in nexvul itself.
