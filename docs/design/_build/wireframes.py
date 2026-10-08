"""Generates docs/design/wireframes/J1..J6 *.html: swim-lane storyboards with low-fidelity grey-box
wireframes of the screen at each step. Self-contained (inline CSS only, no script, no external requests),
light and dark via prefers-color-scheme. Run: python3 docs/design/_build/wireframes.py [--shots]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (ROOT, MOCK_LABEL, esc, css_vars, csp_hash, mark_svg, check_balanced, check_colours,
                    check_no_handlers, check_no_network, shoot, TOKENS)

OUT = os.path.join(ROOT, "docs", "design", "wireframes")
DK = TOKENS["color"]["dark"]

# ---------------------------------------------------------------- wireframe primitives
# Each returns HTML for a grey-box screen. Text in lines is real copy; "~~" renders a grey filler bar.


def _line(s):
    if s == "~~":
        return '<div class="bar"></div>'
    if s.startswith("~~"):
        return '<div class="bar bar-%s"></div>' % s[2:]
    cls = ""
    if s.startswith("!"):
        cls, s = " hl", s[1:]
    elif s.startswith("?"):
        cls, s = " warn", s[1:]
    elif s.startswith("."):
        cls, s = " dimln", s[1:]
    body = esc(s) or "&nbsp;"
    body = re.sub(r"~~(xs|s)?", lambda m: '<span class="ibar ibar-%s"></span>' % (m.group(1) or "m"), body)
    return '<div class="ln%s">%s</div>' % (cls, body)


def term(title, lines):
    return ('<div class="wf wf-term"><div class="wf-chrome"><span></span><span></span><span></span>'
            '<em>%s</em></div><div class="wf-body mono">%s</div></div>' % (esc(title), "".join(_line(l) for l in lines)))


def editor(fname, lines, start=1):
    rows = []
    for i, l in enumerate(lines):
        hl = l.startswith("!")
        rows.append('<div class="eln%s"><span class="gut">%d</span><span>%s</span></div>'
                    % (" hl" if hl else "", start + i, esc(l[1:] if hl else l) or "&nbsp;"))
    return ('<div class="wf wf-ed"><div class="wf-chrome light"><em>%s</em></div><div class="wf-body mono">%s</div></div>'
            % (esc(fname), "".join(rows)))


def dash(active, heading, lines):
    nav = "".join('<div class="nv%s">%s</div>' % (" on" if n == active else "", n)
                  for n in ["Overview", "Findings", "Agents", "Rules", "Suppr.", "History", "Settings"])
    return ('<div class="wf wf-dash"><div class="wf-chrome light"><em>nexvul-report.html (local file)</em></div>'
            '<div class="dash"><div class="dnav">%s</div><div class="dmain"><div class="dh">%s</div>%s</div></div></div>'
            % (nav, esc(heading), "".join(_line(l) for l in lines)))


def gh(kind, title, lines):
    return ('<div class="wf wf-gh"><div class="wf-chrome light"><em>github.com &middot; %s</em></div>'
            '<div class="ghbar"><div class="bar bar-s"></div><div class="bar bar-xs"></div></div>'
            '<div class="wf-body"><div class="dh">%s</div>%s</div></div>' % (esc(kind), esc(title), "".join(_line(l) for l in lines)))


def doc(title, lines):
    return ('<div class="wf wf-doc"><div class="wf-chrome light"><em>%s</em></div><div class="wf-body">%s</div></div>'
            % (esc(title), "".join(_line(l) for l in lines)))


# ---------------------------------------------------------------- journeys
# step: dict(lane, title, action, ids, wf) | decision: dict(decision=q, branches=[(label, outcome, failure_id or "")])

J = {}

J["J1"] = dict(
    slug="J1-first-run", title="J1 First run on a local repo", actor="Developer (U-DEV)",
    goal="Install nexvul, scan an agent project, and understand one finding well enough to fix it, without reading documentation first.",
    lanes=["Developer", "Terminal", "Dashboard (local HTML)"],
    steps=[
        dict(lane=0, title="Reads the README hero", ids="D01", action="Copies the install line.",
             wf=doc("README.md", ["!nexvul", "Static checks for risky patterns in AI-agent code and MCP configs.",
                                  "~~s", "pipx install nexvul", "nexvul scan .", "~~", "~~", "A clean result does not prove your application is secure.",
                                  ".Runs locally. No account, no telemetry, no network."])),
        dict(lane=1, title="Installs and scans", ids="T01", action="Runs nexvul scan . from the project root.",
             wf=term("zsh: my-agent-project", ["$ pipx install nexvul", ".installed package nexvul 0.1.0", "$ nexvul scan .",
                                                ".Analysing  241/312 files  0:07"])),
        dict(decision="Did discovery find analysable files?", branches=[
            ("Yes", "continue", ""), ("No", "T18 SCAN FAILED: nothing to analyse in ./docs. Exit 3. Never prints \"No findings\".", "J1-F10")]),
        dict(decision="Were any agent frameworks recognised?", branches=[
            ("Yes", "continue", ""), ("None", "T19 note: framework rules had nothing to attach to. Scan continues; zero findings mean even less.", "J1-F11")]),
        dict(decision="Was every file analysed inside limits?", branches=[
            ("Yes", "status COMPLETE", ""), ("No", "T05 / T06 PARTIAL SCAN banner as the last line. Exit 3.", "J1-F4")]),
        dict(lane=1, title="Reads findings, highest severity first", ids="T04", action="Picks the top finding.",
             wf=term("zsh: my-agent-project", ["!CRITICAL ████  NEX018  Financial action without human oversight",
                                                ".               ASI02 · ASI09 · confidence medium", "               agent/billing.py:58:9",
                                                "   Flow", "     1 source  agent/billing.py:31", "     3 sink    agent/billing.py:58",
                                                "   Fix  Require human approval before the call.", "~~",
                                                " Result  5 findings · 3 at or above fail-on (high). Exit code 1."])),
        dict(decision="Any findings?", branches=[
            ("Yes", "continue", ""), ("No, COMPLETE", "T02: \"No findings from enabled rules. This does not prove the application is secure.\" Exit 0.", "")]),
        dict(lane=1, title="Learns the rule", ids="U03", action="Runs nexvul explain NEX018.",
             wf=term("zsh", ["$ nexvul explain NEX018", "!NEX018  Financial action without human oversight", "WHAT IT LOOKS FOR", "~~",
                             "HOW TO FIX", "~~s", "WHAT THIS RULE DOES NOT DETECT", "~~s", "SUPPRESSING THIS FINDING",
                             "  # nexvul: ignore[NEX018] -- <reason>"])),
        dict(lane=1, title="Writes the HTML report to share", ids="T21", action="Opens nexvul-report.html from disk.",
             wf=term("zsh", ["$ nexvul scan . --format html --output nexvul-report.html", ".nexvul: wrote nexvul-report.html",
                             ".nexvul: scan complete · 5 at or above fail-on (high) · exit code 1"])),
        dict(lane=2, title="Overview opens offline", ids="H01 H14 H07", action="Reads the completeness strip, then selects the top finding.",
             wf=dash("Overview", "Overview", ["!5 findings at or above fail-on (high). Exit code 1.", "~~", "COMPLETE · 312/312 files · 22/25 rules",
                                                "CRITICAL 1  HIGH 4  MEDIUM 2  LOW 2", "~~s", "~~s"])),
        dict(lane=2, title="Reads the flow and fix", ids="H16 H05", action="Copies the fix; edits agent/billing.py.",
             wf=dash("Findings", "Findings", ["[Critical][High][Medium][Low]  ASI ▾  Rule ▾  File", "!CRITICAL NEX018 Financial action without human oversight",
                                               "1 SOURCE agent/billing.py:31", "2 STEP   agent/billing.py:44", "3 SINK   agent/billing.py:58",
                                               "How to fix  ~~", "Suppress  # nexvul: ignore[NEX018] -- ..."])),
        dict(lane=0, title="Fixes and re-runs", ids="T03 T02", action="Sees the finding gone and the summary updated.",
             wf=term("zsh", ["$ nexvul scan .", "~~", " Result  4 findings · 2 at or above fail-on (high). Exit code 1."])),
    ],
    failures=[
        ("J1-F1", "Python older than 3.12", "pip error, then U05 in doctor", "-", "README states the requirement next to the install line."),
        ("J1-F2", "Path does not exist", "T10", "2", "Path not found: ./agnet. Did you mean ./agent? Nothing was scanned."),
        ("J1-F3", "Broken .nexvul.yml", "T09", "2", "config error in .nexvul.yml:7:3 · rules.disable: unknown key. Did you mean rules.disabled?"),
        ("J1-F4", "Files failed to parse", "T05 T08 H03", "3", "PARTIAL SCAN: 4 of 312 files not analysed. This result is not a clean bill of health."),
        ("J1-F5", "Global time limit hit", "T25", "3", "Limit reached: max_files (1000 of 1,412 discovered)."),
        ("J1-F6", "Ctrl-C", "T20", "130", "Scan interrupted. No result was produced."),
        ("J1-F7", "nexvul crashes", "T11", "4", "nexvul stopped unexpectedly (internal error). Bug-report URL, nexvul doctor hint."),
        ("J1-F8", "Output file exists and is not a report", "T22", "2", "Refusing to overwrite README.md: it is not a nexvul report."),
        ("J1-F9", "Installed into the project venv", "U06", "-", "warn: nexvul is installed in the same environment as the current project."),
        ("J1-F10", "Nothing analysable", "T18", "3", "SCAN FAILED — nothing to analyse in ./docs. Try: nexvul scan ."),
        ("J1-F11", "No framework recognised", "T19", "0/1", "Frameworks: none recognised. 18 of 25 rules had nothing to check."),
    ])

J["J2"] = dict(
    slug="J2-triage", title="J2 Triage an alert in GitHub code scanning", actor="AppSec engineer (U-SEC)",
    goal="Decide from GitHub alone whether an alert is a true positive, a false positive, or needs the developer, and record that decision where GitHub and nexvul can both see it.",
    lanes=["AppSec engineer", "GitHub code scanning", "Developer terminal"],
    steps=[
        dict(lane=1, title="Filters the alert list", ids="G01", action="Filters tool:nexvul, severity Critical and High.",
             wf=gh("Security · Code scanning", "Code scanning alerts", ["tool:nexvul  is:open  severity:critical,high", "!Financial action without human oversight  NEX018  Critical",
                                                                         "External content indexed into a vector store  NEX002  High", "MCP connection without authentication...  NEX007  High", "~~s"])),
        dict(lane=1, title="Opens the alert", ids="G02", action="Reads the message, then Show paths.",
             wf=gh("Alert #41", "Financial action without human oversight", ["!CRITICAL · Tool refund_order calls stripe.Refund.create() with an amount chosen by the model.",
                                                                              "No approval step was found on the path in the scanned code. Confidence: medium. Steps: 3 (Show paths).",
                                                                              "agent/billing.py:58  ~~s", "Show paths: source → step → sink"])),
        dict(lane=1, title="Expands the rule help", ids="G03", action="Reads what the rule does not detect.",
             wf=gh("Alert #41 · rule help", "NEX018 · ASI02 ASI09", ["A finding means nexvul identified a risky pattern.", "What nexvul looked for  ~~", "How to fix  ~~",
                                                                     "What this rule does not detect  ~~", "Suppressing this finding", "# nexvul: ignore[NEX018] -- <reason>"])),
        dict(decision="Is the flow real?", branches=[
            ("Yes", "Assigns to the developer or opens an issue from the alert. Done.", ""),
            ("Mitigated elsewhere", "Go to J3: suppress in code with a justification, so the reason travels with the code.", ""),
            ("nexvul misread the code", "Dismiss as False positive with a comment, and file the FP report linked from rule help.", ""),
            ("Cannot tell", "Asks the developer to run explain and --verbose locally.", "")]),
        dict(lane=2, title="Developer reproduces locally", ids="U03 T12", action="Shares the verbose flow in the alert thread.",
             wf=term("zsh", ["$ nexvul explain NEX018", "$ nexvul scan --verbose agent/", ".Effective config (source per key)", "!Flow 1 source agent/billing.py:31", "~~", "~~s"])),
        dict(decision="Was the run that produced this alert complete?", branches=[
            ("Yes", "Decision recorded.", ""), ("Partial", "G05 tool notification and A03 job summary: N files not analysed. A short alert list may be short because of this.", "J2-F3")]),
        dict(lane=0, title="Records the decision", ids="G04", action="Closes, assigns or links the J3 suppression PR.",
             wf=gh("Alert #41", "Closed · suppressed in source", ["Suppression: inSource", "\"auth enforced by the API gateway (infra/gateway.tf)\"", "~~s"])),
    ],
    failures=[
        ("J2-F1", "Same finding reappears after a refactor", "G01", "-", "Stable partialFingerprints keep the alert; a renamed function may still create a new one."),
        ("J2-F2", "Snippet contains attacker text", "G02", "-", "Snippets come from the scanned repository; treat them as untrusted. Never rendered as Markdown."),
        ("J2-F3", "Results truncated or partial", "G05 A03", "3", "executionSuccessful: false; truncation listed in tool notifications and job summary."),
        ("J2-F4", "SARIF upload rejected", "A07", "-", "The job fails. The reference workflow never uses continue-on-error."),
        ("J2-F5", "Dismissed in GitHub, later suppressed in code", "G04", "-", "SARIF suppressions[] shows as suppressed; both records agree."),
    ])

J["J3"] = dict(
    slug="J3-suppress", title="J3 Suppress a false positive with a justification", actor="Developer (U-DEV), reviewed by AppSec (U-SEC)",
    goal="Silence one finding at one location with a reason a reviewer can read; the suppression stays visible everywhere.",
    lanes=["Developer", "Editor", "Terminal / dashboard", "Pull request (CI)"],
    steps=[
        dict(lane=2, title="Sees the finding", ids="T04", action="Decides auth is enforced by the API gateway.",
             wf=term("zsh", ["!HIGH ███░  NEX006  A2A / agent HTTP endpoint without authentication", "               agent/server.py:41:1", "~~s"])),
        dict(lane=2, title="Looks up the syntax", ids="U03", action="Copies the pre-filled comment.",
             wf=term("zsh", ["$ nexvul explain NEX006", "SUPPRESSING THIS FINDING", "!  # nexvul: ignore[NEX006] -- <why this is mitigated>", "  In CI the justification after -- is required."])),
        dict(lane=1, title="Adds the comment with a reason", ids="C03", action="Saves agent/server.py.",
             wf=editor("agent/server.py", ["from fastapi import FastAPI", "", "!# nexvul: ignore[NEX006] -- auth enforced by the API gateway (infra/gateway.tf)", "app.post(\"/agents/run\")(run_agent)"], start=39)),
        dict(decision="Is the comment valid?", branches=[
            ("Rule ID and reason", "continue", ""), ("No reason", "Locally applied with (no justification); in CI NOT applied and the finding stays active.", "J3-F1"),
            ("No rule ID", "Rejected: write ignore[NEX0nn]. Finding stays active.", "J3-F2"),
            ("Hidden character", "Rejected: contains U+202E. Finding stays active.", "J3-F3")]),
        dict(lane=2, title="Re-runs: finding moves to Suppressed", ids="T17 H20", action="Checks the justification as shown.",
             wf=dash("Suppr.", "Suppressions", ["APPLIED 1   ADDED ON THIS BRANCH 1", "!NEX006 agent/server.py:41 inline", "“auth enforced by the API gateway (infra/gateway.tf)”  Applied", "~~s"])),
        dict(lane=0, title="Commits; hook passes", ids="K01", action="Opens a pull request.",
             wf=term("git commit", ["nexvul..................................................Passed"])),
        dict(lane=3, title="Job summary lists the new suppression", ids="A01", action="Reviewer reads the claim without hunting for it.",
             wf=gh("Actions · job summary", "nexvul — 0 findings at or above high", ["Scan complete. 312 of 312 files analysed · exit code 0",
                                                                                      "!Suppressions added in this pull request (1)", "NEX006  agent/server.py:41  auth enforced by the API gateway ...",
                                                                                      "Configuration  Effective config: .nexvul.yml at base 3f2c1a9"])),
        dict(lane=3, title="Reviewer approves or challenges", ids="G04", action="Alert shows as suppressed in source.",
             wf=gh("Pull request #212", "Review", ["!Changes requested? → developer fixes the code instead", "Approved → merge", "~~s"])),
    ],
    failures=[
        ("J3-F1", "No justification, CI requires one", "C04", "1 if at/above", "Suppression for NEX006 at agent/server.py:41 has no justification. Add one after --. The finding is reported as active."),
        ("J3-F2", "Blanket ignore with no rule ID", "C05", "finding active", "Suppressions must name a rule, e.g. ignore[NEX006]. This comment was ignored."),
        ("J3-F3", "Bidi or invisible characters", "C05", "finding active", "This suppression contains hidden characters (U+202E) and was ignored."),
        ("J3-F4", "Wrong rule ID", "C05", "finding active", "ignore[NEX060] names no rule. Did you mean NEX006?"),
        ("J3-F5", "Stale suppression", "T17", "-", "1 suppression matched nothing (agent/old.py:12)."),
        ("J3-F6", "Rule disabled in .nexvul.yml in the same PR", "C06 A01", "per result", "rules.disabled NEX006 — not applied (config from pull request head)."),
        ("J3-F7", "Comment-like text inside a string", "-", "finding active", "Only real comment tokens are read; visible with --verbose."),
    ])

J["J4"] = dict(
    slug="J4-ci-gating", title="J4 Gate CI with fail-on", actor="Platform engineer (U-PLAT)",
    goal="Fail pull requests on findings at or above a chosen severity, or when the scan could not complete, with a summary that explains either outcome.",
    lanes=["Platform engineer", "Repository", "GitHub Actions", "Pull request"],
    steps=[
        dict(lane=1, title="Adds the reference workflow", ids="D06", action="Pins the Action by commit SHA; fail-on: high.",
             wf=editor(".github/workflows/nexvul.yml", ["on: pull_request", "permissions: {contents: read, security-events: write}", "jobs:", "  nexvul:",
                                                        "    steps:", "      - uses: actions/checkout@<sha>", "        with: {persist-credentials: false}",
                                                        "!      - uses: <owner>/nexvul-action@<sha>", "!        with: {fail-on: high}"])),
        dict(lane=1, title="Commits .nexvul.yml on the default branch", ids="C01", action="Protects it with CODEOWNERS.",
             wf=editor(".nexvul.yml", ["severity:", "  fail_on: high", "exclude:", "  - \"gen/**\"", "suppressions:", "  require_justification: true"])),
        dict(lane=2, title="Action runs in CI mode", ids="T23 T15", action="Log shows where each setting came from.",
             wf=term("Actions log", ["nexvul 0.1.0  scan of . (pull request #212 against main 3f2c1a9)", "  Mode     CI (detected from GITHUB_ACTIONS)",
                                     "!  Config   .nexvul.yml from base ref 3f2c1a9 · 2 changed keys in pull request not applied", "~~", " Result  3 at or above fail-on (high). Exit code 1."])),
        dict(decision="Exit code?", branches=[
            ("0", "Job passes. A02: No findings at or above high from enabled rules. This does not prove the application is secure.", ""),
            ("1", "Job fails. A01 leads with the count at or above threshold.", ""),
            ("3", "Job fails. A03 leads with the PARTIAL SCAN banner and the reasons table.", "J4-F4"),
            ("2", "Job fails. A08 names the bad input or key.", "J4-F2"),
            ("4", "Job fails. A09: nexvul stopped unexpectedly. No half-written SARIF is uploaded.", "")]),
        dict(lane=3, title="PR check and job summary", ids="A05 A01", action="Developer opens the summary from the failed check.",
             wf=gh("Pull request #212 · Checks", "Some checks were not successful", ["!nexvul / scan — nexvul: 3 findings at or above high", "Code scanning results / nexvul — 3 new alerts",
                                                                                 "~~s", "Job summary: Findings at or above high (3) · Suppressions added (1)"])),
        dict(lane=0, title="Requires the nexvul job in branch protection", ids="D06", action="Requires the job, not only the code-scanning check.",
             wf=gh("Settings · Branches", "Branch protection rule: main", ["Require status checks to pass", "!nexvul / scan  (required)", ".Only the job also fails on partial scans."])),
    ],
    failures=[
        ("J4-F1", "pull_request_target or workflow_run with PR-head checkout", "A06", "fail", "nexvul — not run: untrusted checkout under pull_request_target."),
        ("J4-F2", "fail-on value invalid", "A08", "2", "fail-on must be one of: critical, high, medium, low, never."),
        ("J4-F3", "PR raises fail_on to critical", "A01", "per result", "Protections weakened by repository configuration: severity.fail_on — NOT APPLIED (pull request head)."),
        ("J4-F4", "Huge generated files make every run partial", "A03", "3", "Add generated files to exclude on the default branch; exclusions are counted."),
        ("J4-F5", "continue-on-error or || true added", "docs", "-", "Docs explain this turns a partial scan into a passing check; the summary still shows PARTIAL."),
        ("J4-F6", "Missing security-events: write", "A07", "fail", "SARIF upload failed: the workflow token lacks security-events: write."),
        ("J4-F7", "Fork PR, read-only token", "A07", "per result", "Summary written; SARIF kept as an artifact; GitHub's fork limitation explained."),
        ("J4-F8", "Two uploads with the same category", "A07", "fail", "Error names category as the cause."),
    ])

J["J5"] = dict(
    slug="J5-contribute-rule", title="J5 Contribute a rule", actor="Open-source contributor (U-OSS)",
    goal="Turn knowledge of an agent attack pattern into a rule that ships, without guessing what evidence maintainers need.",
    lanes=["Contributor", "Terminal / editor", "GitHub issue and PR", "Maintainers and CI"],
    steps=[
        dict(lane=2, title="Reads Propose a rule", ids="D05", action="Reads the gates and the template.",
             wf=doc("CONTRIBUTING.md", ["!Propose a rule", "1 Proposal issue (no code)", "2 Triage", "3 ID allocated by a maintainer", "4 Rule + tests + docs",
                                        "5 Benchmark within the FP budget", "6 Merged as experimental", "7 Default after one release"])),
        dict(lane=1, title="Checks existing coverage", ids="U01 U02 U03", action="Reads what the nearest rule does not detect.",
             wf=term("zsh", ["$ nexvul rules --asi ASI07", "NEX006  A2A / agent HTTP endpoint without authentication", "NEX007  MCP connection without authentication...",
                             "~~", "$ nexvul explain NEX008", "!WHAT THIS RULE DOES NOT DETECT", "~~"])),
        dict(lane=2, title="Opens a rule proposal issue", ids="D05", action="Fills Threat, OWASP mapping, detection, examples, FP/FN.",
             wf=gh("Issues · new", "Rule proposal: A2A card fetched over cleartext", ["Threat  ~~", "OWASP mapping  ASI07", "Positive examples  ~~", "Negative examples  ~~", "False positives  ~~s"])),
        dict(decision="Maintainer triage", branches=[
            ("Accepted for design", "continue", ""), ("Needs evidence", "Comment lists the missing evidence.", ""),
            ("Out of scope", "Closed with the taxonomy exclusion category (e.g. not statically detectable).", "")]),
        dict(lane=3, title="ID allocated", ids="-", action="Maintainer assigns NEX026; IDs are never reused.",
             wf=gh("Issue #88", "Accepted · NEX026 allocated", ["!Rule ID: NEX026", "Next: rule, tests (positive, negative, edge_cases, adversarial), docs/rules/NEX026.md"])),
        dict(lane=1, title="Writes the rule, tests and docs; runs locally", ids="D04", action="Expects zero high-confidence findings on benchmarks/safe.",
             wf=term("zsh", ["$ pytest tests/rules/test_nex026.py", ".14 passed", "$ nexvul scan benchmarks/safe --rules NEX026", "!Result  0 findings · scan complete. Exit code 0."])),
        dict(lane=3, title="CI posts per-rule precision and recall", ids="-", action="Contributor reads which safe/ cases fired.",
             wf=gh("PR #301 · bot comment", "Benchmark: NEX026", ["precision  ~~s   recall  ~~s", "!safe/ cases that fired: 1 (benchmarks/safe/a2a_local.py)", "FP budget (DEC-0002): ~~xs"])),
        dict(decision="Within the FP budget?", branches=[
            ("Yes", "Review gates, then merged as experimental (off by default); promoted after a release cycle.", ""),
            ("No", "CI comment lists exactly which safe/ cases fired.", "")]),
    ],
    failures=[
        ("J5-F1", "Message template interpolates scanned content unsafely", "lint", "fail", "Message templates may use only named, escaped placeholders."),
        ("J5-F2", "Help links to a non-allowlisted host", "lint", "fail", "Built-in help may link only to OWASP, MITRE CWE, framework docs and nexvul docs."),
        ("J5-F3", "Rule message uses a banned phrase", "copy lint", "fail", "\"vulnerable\" is not allowed; write \"finding\" or name the risky pattern."),
        ("J5-F4", "Duplicates an existing rule's sink", "dedupe check", "comment", "Overlaps NEX006 on the same route; dedupe so there is one finding per route."),
    ])

J["J6"] = dict(
    slug="J6-pre-commit", title="J6 Pre-commit hook", actor="Developer (U-DEV)",
    goal="Catch findings in staged files before they are committed, without pretending a staged-file scan is a full scan.",
    lanes=["Developer", "Editor", "Terminal (pre-commit)", "CI"],
    steps=[
        dict(lane=1, title="Adds the hook, pinned by SHA", ids="D06", action="Runs pre-commit install.",
             wf=editor(".pre-commit-config.yaml", ["repos:", "!  - repo: https://github.com/<owner>/nexvul", "!    rev: <commit sha>", "    hooks:", "      - id: nexvul"])),
        dict(lane=0, title="Commits", ids="-", action="git commit -m \"Add refund tool\"",
             wf=term("zsh", ["$ git commit -m \"Add refund tool\""])),
        dict(decision="Relevant files staged?", branches=[
            ("No", "K04: (no files to check)Skipped. nexvul is not invoked. Exit 0.", ""), ("Yes", "continue", "")]),
        dict(decision="Findings at or above fail-on? Files parsed?", branches=[
            ("None", "K01 Passed. Silent on success.", ""), ("Findings", "K02 commit blocked.", ""),
            ("Parse error", "K05 commit blocked with the parse-error line. Exit 3.", "J6-F1")]),
        dict(lane=2, title="Commit blocked", ids="K02 K03", action="Fixes, or bypasses with --no-verify (their choice; CI still scans).",
             wf=term("git commit", ["nexvul..............................................Failed", ".- exit code: 1",
                                    "!agent/billing.py:58  CRITICAL  NEX018  Financial action without human oversight", "  fix: require approval before stripe.Refund.create()",
                                    "Commit blocked by nexvul (fail-on: high).", "?Staged-file scan: cross-file flows not checked. Run nexvul scan . for a full scan."])),
        dict(lane=3, title="CI runs the full scan", ids="A01", action="Cross-file flows are checked here.",
             wf=gh("Actions · job summary", "nexvul — 1 finding at or above high", ["Scan complete. 312 of 312 files analysed · exit code 1", "!CRITICAL NEX018 agent/billing.py:58", "~~s"])),
    ],
    failures=[
        ("J6-F1", "Staged file fails to parse", "K05", "3", "Commit blocked: agent/legacy.py could not be parsed (line 12). Fix it or commit without the hook."),
        ("J6-F2", "Developer uses --no-verify", "-", "-", "The hook does not run; CI still scans the pull request."),
        ("J6-F3", "Flow crosses an unstaged file", "K03", "-", "Not visible to a staged-file scan; the scope reminder is printed every time."),
        ("J6-F4", "Hook installed into the project venv", "U06", "-", "nexvul doctor warns that the project's dependencies can load code into nexvul."),
    ])


# ---------------------------------------------------------------- page

CSS = r"""
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.5 var(--body)}
code,.mono{font-family:var(--mono)}
.band{background:var(--mock-band);color:var(--mock-band-text);font-size:12px;padding:6px 16px;text-align:center;border-bottom:1px solid var(--border)}
.band strong{letter-spacing:.06em;text-transform:uppercase}
.wrap{max-width:1320px;margin:0 auto;padding:24px 24px 48px}
header.top{display:flex;align-items:center;gap:10px;margin-bottom:6px;color:var(--text)}
header.top .wm{font-family:var(--mono);font-weight:700;letter-spacing:-.02em}
h1{font-size:26px;margin:4px 0 6px;letter-spacing:-.01em}
.goal{color:var(--muted);max-width:90ch;margin:0 0 4px}
.meta{font-size:12px;color:var(--dim);margin:0 0 18px}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12px;color:var(--muted);margin:0 0 16px;padding:0;list-style:none}
.legend li{display:flex;gap:6px;align-items:center}
.k{display:inline-block;width:18px;height:12px;border:1.5px solid var(--border-strong);border-radius:3px}
.k-dec{transform:rotate(45deg);width:11px;height:11px}
.k-fail{border-style:dashed;border-color:var(--sev-critical)}
.lanes{display:grid;gap:0;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--card)}
.lhead{display:grid;background:var(--inset);border-bottom:1px solid var(--border)}
.lhead div{padding:8px 12px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;color:var(--muted);border-left:1px solid var(--border)}
.lhead div:first-child{border-left:0}
.row{display:grid;position:relative;border-top:1px solid var(--border-subtle)}
.row:first-of-type{border-top:0}
.cell{padding:12px;border-left:1px dashed var(--border);min-height:24px}
.cell:first-child{border-left:0}
.step{border:1px solid var(--border-strong);border-radius:8px;background:var(--card);padding:10px;box-shadow:0 1px 2px var(--shadow)}
.sh{display:flex;gap:8px;align-items:baseline;margin-bottom:8px}
.sn{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:22px;border-radius:11px;background:var(--text);color:var(--page);font-size:11px;font-weight:700}
.st{font-weight:650}
.ids{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--accent-text);white-space:nowrap}
.act{margin:8px 0 0;font-size:12px;color:var(--text)}
.act b{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-right:4px}
.dec{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:8px 12px;align-items:stretch;padding:12px;background:var(--inset)}
.q{display:flex;align-items:center;gap:10px;font-weight:650;min-width:240px}
.dia{display:inline-block;width:14px;height:14px;border:2px solid var(--text);transform:rotate(45deg);flex:none}
.br{flex:1 1 200px;border:1px solid var(--border-strong);border-radius:8px;padding:6px 10px;font-size:12px;background:var(--card)}
.br b{display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.br-fail{border-style:dashed;border-color:var(--sev-critical)}
.br-fail b{color:var(--sev-critical)}
.br a{color:var(--accent-text)}
.wf{border:1px solid var(--border);border-radius:6px;overflow:hidden;font-size:11px;line-height:1.45}
.wf-chrome{display:flex;gap:5px;align-items:center;padding:5px 8px;background:__T_CHROME__;color:__T_DIM__}
.wf-chrome span{width:7px;height:7px;border-radius:4px;background:__T_DIM__}
.wf-chrome em{font-style:normal;margin-left:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.wf-chrome.light{background:var(--inset);color:var(--muted);border-bottom:1px solid var(--border)}
.wf-body{padding:8px 10px}
.wf-term .wf-body{background:__T_BG__;color:__T_TEXT__}
.wf-term .ln{white-space:pre-wrap;word-break:break-word}
.wf-term .hl{color:__T_TEXT__;font-weight:700;background:__T_HL__}
.wf-term .warn{color:__T_WARN__}
.wf-term .dimln{color:__T_DIM__}
.wf-term .bar{background:__T_HL__}
.ln{white-space:pre-wrap;word-break:break-word}
.hl{font-weight:700;background:var(--accent-tint)}
.dimln{color:var(--muted)}
.bar{height:7px;border-radius:4px;background:var(--border);margin:5px 0;width:92%}
.bar-s{width:60%}.bar-xs{width:30%}
.ibar{display:inline-block;vertical-align:middle;height:7px;border-radius:4px;background:var(--border);width:80px}.ibar-s{width:48px}.ibar-xs{width:28px}
.wf-term .ibar{background:__T_HL__}
.wf-ed .wf-body{background:var(--card)}
.eln{display:flex;gap:8px;white-space:pre-wrap;word-break:break-word}
.eln .gut{color:var(--dim);min-width:18px;text-align:right;flex:none}
.eln.hl{background:var(--accent-tint)}
.dash{display:grid;grid-template-columns:64px 1fr;min-height:120px}
.dnav{background:var(--nav);border-right:1px solid var(--border);padding:6px 4px}
.nv{font-size:10px;color:var(--muted);padding:2px 4px;border-radius:3px}
.nv.on{background:var(--accent-tint);color:var(--accent-text);font-weight:700}
.dmain{padding:8px 10px}
.dh{font-weight:700;margin-bottom:4px}
.ghbar{display:flex;gap:8px;padding:6px 10px;border-bottom:1px solid var(--border);background:var(--inset)}
.ghbar .bar{margin:0;height:6px}
.fails{margin-top:28px}
h2{font-size:18px;margin:0 0 10px}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{text-align:left;vertical-align:top;padding:8px 10px;border-top:1px solid var(--border-subtle)}
thead th{border-top:0;background:var(--inset);font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
td.id{font-family:var(--mono);font-weight:700;color:var(--sev-critical);white-space:nowrap}
td.copy{font-family:var(--mono);font-size:12px}
tr:target{background:var(--accent-tint)}
.foot{margin-top:24px;font-size:12px;color:var(--muted)}
@media (max-width:900px){.lhead{display:none}.row{display:block}.cell:empty{display:none}.cell{border-left:0}
  .cell[data-lane]::before{content:attr(data-lane);display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:700;margin-bottom:6px}}
@media (max-width:600px){.wrap{padding:16px}table{display:block;overflow-x:auto}}
"""


def page(key, j):
    n = len(j["lanes"])
    cols = "grid-template-columns:repeat(%d,minmax(0,1fr))" % n
    rows, sn = [], 0
    for s in j["steps"]:
        if "decision" in s:
            brs = []
            for label, outcome, fid in s["branches"]:
                cls = " br-fail" if fid else ""
                link = ' <a href="#%s">%s</a>' % (fid, fid) if fid else ""
                brs.append('<div class="br%s"><b>%s</b>%s%s</div>' % (cls, esc(label), esc(outcome), link))
            rows.append('<div class="row cols"><div class="dec"><div class="q"><span class="dia" aria-hidden="true"></span>%s</div>%s</div></div>'
                        % (esc(s["decision"]), "".join(brs)))
            continue
        sn += 1
        cells = []
        for i in range(n):
            if i == s["lane"]:
                cells.append('<div class="cell" data-lane="%s"><div class="step"><div class="sh"><span class="sn">%d</span>'
                             '<span class="st">%s</span><span class="ids">%s</span></div>%s<p class="act"><b>User action</b>%s</p></div></div>'
                             % (esc(j["lanes"][i]), sn, esc(s["title"]), esc(s["ids"]), s["wf"], esc(s["action"])))
            else:
                cells.append('<div class="cell"></div>')
        rows.append('<div class="row cols">%s</div>' % "".join(cells))
    fails = "".join('<tr id="%s"><td class="id">%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="copy">%s</td></tr>'
                    % (f[0], f[0], esc(f[1]), esc(f[2]), esc(f[3]), esc(f[4])) for f in j["failures"])
    T = DK
    css = (css_vars() + CSS.replace("__T_BG__", T["surface"]["inset"]).replace("__T_TEXT__", T["text"]["default"]["value"])
           .replace("__T_DIM__", T["text"]["muted"]["value"]).replace("__T_CHROME__", T["surface"]["raised"])
           .replace("__T_HL__", T["surface"]["card_hover"]).replace("__T_WARN__", T["severity"]["medium"]["text"])
           + ".cols{%s}\n.lhead{%s}\n" % (cols, cols))
    csp = "default-src 'none'; style-src %s; img-src data:; base-uri 'none'" % csp_hash(css)
    others = " &middot; ".join('<a href="%s.html">%s</a>' % (J[k]["slug"], k) if k != key else "<strong>%s</strong>" % k for k in J)
    html_ = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="%(csp)s">
<title>%(key)s wireframes</title><style>%(css)s</style></head>
<body>
<div class="band" role="note"><strong>%(mock)s</strong> &middot; Low-fidelity wireframes; copy is real, layout is indicative. Journeys: %(others)s &middot; <a href="../design-pack.html">Design pack</a></div>
<div class="wrap">
<header class="top">%(mark)s<span class="wm">nexvul</span><span class="meta">user journey storyboard</span></header>
<h1>%(title)s</h1>
<p class="goal"><strong>Goal.</strong> %(goal)s</p>
<p class="meta">Actor: %(actor)s &middot; Screen IDs from screen-inventory.md &middot; Flow diagram: flows/%(key)s-*.svg (J1&ndash;J5)</p>
<ul class="legend"><li><span class="k" aria-hidden="true"></span>Step: the screen the user sees, and what they do</li>
<li><span class="k k-dec" aria-hidden="true"></span>Decision point</li><li><span class="k k-fail" aria-hidden="true"></span>Failure branch (links to the table)</li></ul>
<div class="lanes" aria-label="%(title)s swim lanes">
<div class="lhead" aria-hidden="true">%(lh)s</div>
%(rows)s
</div>
<section class="fails" aria-labelledby="fh"><h2 id="fh">Failure paths</h2>
<table><thead><tr><th scope="col">ID</th><th scope="col">Trigger</th><th scope="col">Screen</th><th scope="col">Exit</th><th scope="col">What the user sees (copy)</th></tr></thead><tbody>%(fails)s</tbody></table></section>
<p class="foot">%(mock)s. Generated by docs/design/_build/wireframes.py. %(disc)s</p>
</div></body></html>
""" % dict(csp=csp, key=key, css=css, mock=MOCK_LABEL, others=others, mark=mark_svg(20), title=esc(j["title"]),
           goal=esc(j["goal"]), actor=esc(j["actor"]), lh="".join('<div>%s</div>' % esc(l) for l in j["lanes"]),
           rows="\n".join(rows), fails=fails, disc=esc(TOKENS["copy"]["disclaimer"]))
    return html_


def build():
    os.makedirs(OUT, exist_ok=True)
    paths = []
    for k, j in J.items():
        h = page(k, j)
        name = "%s.html" % j["slug"]
        check_balanced(h, name)
        check_colours(h, name)
        check_no_handlers_relaxed(h, name)
        check_no_network(h, name)
        p = os.path.join(OUT, name)
        open(p, "w").write(h)
        paths.append(p)
        print("wrote", p)
    return paths


def check_no_handlers_relaxed(h, name):
    # wireframes use style attributes nowhere either; same check as the dashboard
    check_no_handlers(h, name)


def shots(paths):
    for p in paths:
        out = p[:-5] + ".png"
        shoot("file://" + p, out, 1320, 4200, crop=True)
        print("shot", out)


if __name__ == "__main__":
    ps = build()
    if "--shots" in sys.argv:
        shots(ps)
