# nexvul — Roadmap

> Status: **Proposed** (Phase 0 artefact). Owner: Engineering Operations / Benchmarking lead.
> Approver: Principal Supervisor, then the human product owner.
> Binding inputs: `docs/brief/master-brief.md` (§4–6, 15, 18, 21–23, 26–27, 30, 33),
> `docs/research/competitors/README.md`, `docs/architecture.md`, `docs/adr/0001-*`.
> No calendar dates. Sizing: **S** ≈ one focused work package, **M** ≈ several packages / one sub-team,
> **L** ≈ multi-sub-team effort with real unknowns. Sizes are relative, not estimates of hours.

## 0. Sequencing principle

The brief §27 lists phases in a breadth-first order (rules → data flow → frameworks → JS/TS → integrations →
benchmarking → hardening → release). Following that order literally would mean nothing usable ships until
Phase 9, and benchmarking would arrive after the rules it is supposed to keep honest.

This roadmap keeps the brief's phase **names and numbers** but changes **what is inside** the early phases so that
a **thin, honest vertical slice** ships first:

> Python only · 2–3 high-precision rules · terminal + JSON + SARIF + HTML output · seed benchmark with published
> per-rule precision/recall · a clear "clean scan ≠ secure" statement · released as a clearly-labelled pre-release.

Breadth (cross-file taint, frameworks, JS/TS, more rules) is then added behind a regression-gated benchmark.

**Pulled forward** (requires Supervisor approval — this is a sequencing change, not a scope change, so it does not
trigger §32, but it is recorded as DEC-0001 in `.nexvul/decisions/`):

| Item | Brief phase | Moved into |
|------|-------------|-----------|
| SARIF reporter | 6 | 2 |
| HTML report (self-contained, offline) | not in §27 (competitive differentiator) | 2 |
| Benchmark harness + seed corpus | 7 | 1 (harness) / 2 (seed corpus) |
| Malicious-input hardening of file loading | 8 | 1 (baseline), 8 (red team) |
| Pre-release packaging | 9 | 2 (`0.1.0a1`, pre-release only) |
| CI for nexvul itself (lint, type, test, dependency audit) | 6/19 | 1 |

Why: the competitive review shows the field is crowded with tools that have many rules and weak evidence (only one
publishes F1, self-labelled). nexvul's credibility comes from **measured precision**, **working output a team can
share**, and **fully-local operation** — all achievable with a small rule set. Cross-file taint and working JS/TS
are the long-term moat, but they must be built on a harness that can prove they help.

## 1. Workstreams (run across phases)

| ID | Workstream | Lead role(s) | Notes |
|----|------------|--------------|-------|
| WS-A | Analysis engine | 04 Python, 05 JS/TS, 14 Taint | Parser → IR → taint → rules |
| WS-B | Detection content | 02 Research, 03 OWASP, 06–13 domain + rule engineer | Rules follow the §6 lifecycle |
| WS-C | Quality & evidence | 15 Benchmarking, 16 Adversarial, 17 FP Hunter, 18 QA | Owns gates, metrics, corpus |
| WS-D | Security of nexvul | 01 Supervisor, 19 DevSecOps, 16 Adversarial | Hostile-input defence, supply chain |
| WS-E | **Distribution & adoption** | 20 Documentation, 21 Release, 19 DevSecOps, 15 Benchmarking | See §4 — this is the hard part |

## 2. Phase plan

Each phase lists: Goal · Deliverables · Entry criteria · Exit criteria · Quality gates · Key risks · Dependencies ·
Size. **Exit criteria are evidence-based**: a phase is not exited by assertion (brief §33). Every phase ends with a
phase report (`.nexvul/templates/phase-report.md`, brief §34) reviewed by the Supervisor.

Common quality gates (brief §30) apply to every phase that changes detection or analysis code:
`G1` requirement understood · `G2` threat model considered · `G3` architecture reviewed · `G4` tests exist ·
`G5` positive/negative/adversarial cases · `G6` FPs investigated · `G7` performance measured · `G8` docs ·
`G9` OWASP mapping · `G10` security reviewed. Any critical gate failure ⇒ phase not complete.

---

### Phase 0 — Research & foundations (current) · Size **L**

**Goal.** Decide what to build and how to prove it works, before writing scanner code.

**Deliverables.** `docs/research/**`, `docs/threat-model.md`, `docs/architecture.md`, `docs/detection-taxonomy.md`,
`docs/owasp/`, ADR-0001 (parser/static analysis), `docs/design/` (UX, screens, flows), this roadmap,
`docs/benchmark-strategy.md`, `docs/test-strategy.md`, `.nexvul/` workspace with templates, tasks and 21 agent role
definitions, `benchmarks/schema/example.schema.json`.

**Entry.** Brief accepted by product owner.

**Exit.**
- All §35 deliverables exist and each has a named reviewer who is not its author.
- ADR-0001 moved from *Proposed* to *Accepted* by the Supervisor (or alternatives escalated to the human per §32.1).
- Thin-slice rule candidates (§3) each have a completed rule-proposal answering every §17 question, or are dropped.
- FP budget (benchmark-strategy §8) approved or amended by the human.
- Supervisor presents findings + implementation sequence; **human approves start of Phase 1** (brief §35).

**Gates.** G1, G2, G3, G9 (no code yet, so G4–G7 are N/A and recorded as such).

**Risks.** Analysis paralysis; research that invents facts (mitigation: every external claim cited or marked
unverified); concurrent agents writing conflicting docs (mitigation: one owner per file, handoffs in
`.nexvul/handoffs/`).

**Dependencies.** None.

---

### Phase 1 — Foundation · Size **M**

**Goal.** A safe, deterministic skeleton that can walk a hostile repository, parse Python, emit an empty-but-valid
report, and be measured.

**Deliverables.**
- Package skeleton per brief §9; `nexvul scan`, `nexvul version`, `nexvul rules`, `nexvul doctor`.
- Repository discovery with **safe file loading**: no symlink following outside root, size/depth/count limits,
  binary detection, encoding handling, exclude globs, deterministic ordering (architecture §9).
- Python parsing via stdlib `ast` with per-file time/size/recursion guards; parse failures become diagnostics,
  never crashes.
- Finding model + JSON schema v0 (architecture §7) with stable fingerprints.
- Terminal reporter (Rich) and JSON reporter.
- Rule plugin API (architecture §6) with a no-op test rule and the `# nexvul-expect:` fixture convention.
- Test framework per `docs/test-strategy.md`: pytest layout, golden-file harness, Hypothesis setup, malicious-input
  suite v0 (giant file, deep nesting, symlink loop, path traversal names, binary, invalid UTF-8).
- **Benchmark harness v0**: `benchmarks/` layout, metadata schema validation, runner that scores expected vs actual
  findings, synthetic-repo generator for 100/1k/5k/10k files (no rules needed yet — measures discovery+parse).
- CI for nexvul: lint, type-check, tests, coverage report, dependency audit, SBOM generation; nexvul scans itself.
- Repo hygiene files: LICENSE, README stub with the mandatory disclaimer, CONTRIBUTING, SECURITY,
  CODE_OF_CONDUCT, CHANGELOG (brief §26).

**Entry.** Phase 0 exit approved by human. ADR-0001 accepted.

**Exit.**
- `nexvul scan` runs on the malicious-input suite with zero crashes, zero hangs past the configured limit, and
  zero network access (verified by a test that runs with networking blocked).
- Golden-file tests for terminal and JSON reporters pass.
- Harness produces a baseline perf report (runtime, peak RSS, files/sec) for 100/1k/5k/10k synthetic files —
  numbers are recorded, not targeted yet.
- Coverage on `core/` discovery and file-loading ≥ the target in test-strategy §9.

**Gates.** G1–G4, G7, G8, G10. (G5/G6/G9 N/A: no rules.)

**Risks.** Over-engineering the IR before a rule needs it (mitigation: IR grows only when a slice rule needs it);
discovery defects that let hostile repos escape the root (mitigation: Adversarial agent red-teams discovery before
exit).

**Dependencies.** ADR-0001; architecture §6–9; test-strategy.

---

### Phase 2 — Thin vertical slice: initial rules + all four outputs · Size **M**

**Goal.** Ship something real and honest: a small number of rules a security engineer would not mute, with outputs
they can put in CI and share.

**Deliverables.**
- 2–3 rules chosen from the candidates in §3, each through the **full §6 lifecycle** (research → … → supervisor
  approval → docs). Intra-procedural taint only (architecture §3.2 "Phase 1").
- `tests/rules/<RULE>/{positive,negative,edge_cases,adversarial}/` for each rule.
- **SARIF 2.1.0 reporter** validated against the OASIS schema and GitHub code-scanning ingestion expectations
  (`docs/research/tooling/sarif.md`).
- **HTML report**: one self-contained file, no external fetches (no CDN, fonts, analytics), every scanned-repo
  string HTML-escaped, strict CSP meta tag, opens offline. Shows the finding, the step-by-step flow, why it
  matters, remediation, and the "clean scan ≠ secure" statement. Design from `docs/design/`.
- `nexvul explain <RULE>`; `docs/rules/<RULE>.md` per rule; `docs/owasp/` mapping entries.
- **Seed benchmark**: `benchmarks/vulnerable/`, `benchmarks/safe/`, `benchmarks/adversarial/` cases for each rule,
  double-labelled; first per-rule TP/FP/FN/precision/recall/F1 report; held-out split created (benchmark-strategy §10).
- Pre-release `0.1.0a1` packaging (build only; publishing needs Release Engineer + Supervisor approval and the human
  is informed). README states exactly which rules exist, what they do **not** detect, and links the benchmark report.

**Entry.** Phase 1 exit. Rule proposals for the chosen candidates approved by Supervisor.

**Exit.**
- Each shipped rule meets the approved FP budget on the seed corpus **and** on the held-out set.
- Each rule has an adversarial report and an FP-triage record; known misses are documented, not hidden.
- SARIF validates against schema; a test uploads-shape check passes (offline fixture; real upload is exercised in
  Phase 6).
- HTML report passes an XSS test suite (malicious filenames, code snippets, messages containing markup/script).
- Benchmark report generated by the harness, committed alongside the code revision it measured.

**Gates.** G1–G10, all required.

**Risks.** Choosing rules that are easy rather than useful; HTML report becoming an XSS vector (scanned content is
hostile); temptation to publish before precision is measured; slice rules depending on cross-file flow (excluded by
design — rules that need it wait for Phase 3).

**Dependencies.** Phase 1; `docs/detection-taxonomy.md`; `docs/design/`; SARIF research.

---

### Phase 3 — Data flow: symbols, call graph, cross-file taint · Size **L**

**Goal.** Build the differentiator: taint that crosses function and module boundaries (brief §5.14 example
`web.py → memory.py → agent.py`).

**Deliverables.** Symbol tables; import resolution (aliases, re-exports, relative imports); function summaries
(architecture §3.2 Phase 2); cross-file summaries and call graph (Phase 3); flow evidence chain in findings; cache
keyed by content hash. Slice rules upgraded to use cross-file flow **behind a flag** until benchmark proves gain.

**Entry.** Phase 2 exit. Benchmark harness can report per-rule deltas between two revisions.

**Exit.**
- Cross-file cases in `benchmarks/vulnerable/` and `adversarial/` (≥ the per-rule minimum in benchmark-strategy §4)
  detected; precision on `safe/` and held-out does not regress beyond the regression tolerance.
- Perf at 5k/10k synthetic files measured; peak RSS bounded per architecture §8.4.
- Taint engine has property-based tests (Hypothesis) for termination and monotonicity.

**Gates.** G1–G10.

**Risks.** Precision collapse from over-approximation; non-termination on recursive code; perf blow-up. Mitigation:
summaries with bounded depth, widening, per-file budgets; flag-gated rollout.

**Dependencies.** Phase 2 harness; ADR for summary design (new ADR required).

---

### Phase 4 — Framework intelligence · Size **L**

**Goal.** Recognise LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP (Python) constructs as
**declared data** (sources, sinks, sanitisers, capabilities) rather than hard-coded logic.

**Deliverables.** One recogniser module per framework; framework taint specs (architecture §3.5); capability
model for ASI10 (architecture §4); graph model for ASI08 (architecture §5); `benchmarks/frameworks/<fw>/` cases per
framework; framework-support matrix in docs listing **tested versions only** (brief §33).

**Entry.** Phase 3 exit (rules need cross-file flow through framework wrappers).

**Exit.** For each claimed framework: recogniser tests, ≥ 1 real-world project from the verified candidate list
scanned and triaged, framework matrix states versions tested. Unclaimed frameworks are explicitly listed as
unsupported.

**Gates.** G1–G10.

**Risks.** Framework API churn; fake framework metadata in hostile repos (brief §2); overfitting rules to one
framework (brief §5.6). Mitigation: version-pinned fixtures; recognisers rely on import resolution not names alone.

**Dependencies.** Phase 3.

---

### Phase 5 — JS/TS analysis · Size **L**

**Goal.** Working JS/TS analysis (competitive gap: every competitor is heuristic or broken here).

**Deliverables.** tree-sitter-based parsing per ADR-0001 with error recovery and resource limits; CST → shared IR;
imports/exports, async flows, tool/agent definitions, MCP TS SDK, LangChain.js / LangGraph.js / OpenAI Agents JS
recognisers; JS/TS fixtures for every rule that claims JS/TS support.

**Entry.** Phase 3 exit (IR stable). Phase 4 may run in parallel once the IR contract is frozen.

**Exit.** Every rule that advertises JS/TS has JS/TS positive/negative/adversarial tests and benchmark cases;
malformed-JS/TS fuzzing finds no crash; `docs/framework-support.md` lists JS/TS support per rule truthfully.

**Gates.** G1–G10.

**Risks.** Native-dependency supply-chain risk (tree-sitter wheels — §32.4 escalation if risk is significant);
TS-specific syntax gaps; claiming support that is not tested.

**Dependencies.** ADR-0001; Phase 3 IR.

---

### Phase 6 — Integrations · Size **M**

**Goal.** Make nexvul trivially adoptable in CI.

**Deliverables.** GitHub Action (composite or Docker per ADR) with `fail-on`, SARIF upload, pinned dependencies;
pre-commit hook (`id: nexvul`) with staged-file mode; `.nexvul.yml` (brief §14); baseline/incremental mode
(suppress pre-existing findings by fingerprint without hiding them from reports); exit-code contract;
`docs/integrations/`.

**Entry.** Phase 2 exit (SARIF exists). Can start in parallel with Phases 3–5.

**Exit.** Action tested in a sandbox repository against real GitHub code scanning; pre-commit tested with
`pre-commit try-repo`; config fuzzed (malicious `.nexvul.yml`); action never sends source anywhere except the
user's own GitHub code-scanning upload, and that is documented.

**Gates.** G1, G3, G4, G7, G8, G10.

**Risks.** Action supply-chain (tag hijack, unpinned actions); SARIF upload limits; GitHub API changes.

**Dependencies.** Phase 2 SARIF; DevSecOps release pipeline.

---

### Phase 7 — Benchmarking (full corpus & publication) · Size **M**

**Goal.** Independent-grade evidence, published.

**Deliverables.** `benchmarks/real_world/` populated from the verified candidate list (pinned commits, not
vendored); full per-rule report; perf report at 100/1k/5k/10k; methodology page; comparison runs against
competitors **only where their licences and terms allow and only with their published configuration**; external
labellers invited for a subset (addresses the "self-labelled" weakness of the incumbent).

**Entry.** Phases 3–5 deliver the rules to be measured. (Harness and seed corpus already exist since Phases 1–2.)

**Exit.** Benchmark report reproducible from a clean checkout by one documented command; every number traceable to
a commit and a corpus revision; FP budget met or rule demoted/disabled per benchmark-strategy §8.

**Gates.** G6, G7, G8 plus benchmark-strategy §9 CI gates.

**Risks.** Overfitting to the corpus (held-out set + rotation); licence errors in real-world references (§32.7);
cherry-picked comparisons (publish full method and raw data).

**Dependencies.** Phases 3–6.

---

### Phase 8 — Hardening (red-team nexvul) · Size **M**

**Goal.** nexvul survives hostile repositories and hostile users.

**Deliverables.** Full brief §19 suite; ReDoS audit of every regex; resource-exhaustion tests under memory/time
caps; fuzzing campaigns (Hypothesis + coverage-guided where practical) of parsers, config loader, SARIF/HTML
writers; prompt-injection-in-comments tests (nexvul has no LLM by default, but output must not be manipulable into
misleading text); signed releases; SBOM; reproducible build check; threat-model refresh.

**Entry.** Feature-complete for 1.0 scope.

**Exit.** Adversarial report with no open critical/high issues; all fixes have regression tests; SECURITY.md
process exercised once (dry run).

**Gates.** G2, G4, G10.

**Risks.** Discovering architectural flaws late (mitigated by baseline hardening already in Phase 1).

**Dependencies.** All prior phases.

---

### Phase 9 — Release 1.0 · Size **S**

**Goal.** A stable, trustworthy public release.

**Deliverables.** Semver 1.0.0; CHANGELOG; PyPI publish (trusted publishing); GitHub Release with SBOM and
signatures; Marketplace listing for the Action; docs site; **Release Readiness Report** (brief §34, brutally honest).

**Entry.** Phase 8 exit; human approval for irreversible publication (§32.6).

**Exit.** Published artefacts verified by installing from PyPI in a clean environment and scanning the benchmark
corpus with identical results to CI.

**Gates.** All.

**Risks.** Publishing irreversible mistakes (name squatting, wrong metadata). Mitigation: TestPyPI dry run; human
sign-off.

**Dependencies.** Everything.

## 3. Thin-slice rule candidates (Phase 2)

Proposals only. Final rule IDs, titles and severities come from `docs/detection-taxonomy.md` and an approved
rule-proposal (`.nexvul/templates/rule-proposal.md`). Selection criteria: detectable **intra-procedurally in
Python**, a concrete sink, explainable evidence, and a plausible precision ≥ the high-confidence budget.

| Slot | Risk | Candidate pattern | Why high-precision is plausible | Main FP risk to study |
|------|------|-------------------|---------------------------------|-----------------------|
| S1 | ASI06 | Content from an HTTP fetch (`requests`/`httpx`/`urllib`) reaches a vector-store or long-term-memory write in the same function without an identified validation step | Concrete source and sink APIs; flow is visible in one function | Trusted internal URLs; content already validated by a helper (needs sanitiser model) |
| S2 | ASI08 | Agent iteration/recursion limit explicitly disabled or set unbounded in a recognised constructor call | Literal configuration value — little inference | Frameworks whose semantics for `None`/large values differ by version; must be verified per framework version before shipping |
| S3 | ASI07 | MCP / A2A client connecting to a **literal non-loopback `http://`** endpoint, or with auth explicitly absent where the API takes it | Literal URL + known client API | Local dev / test code; docs examples; env-driven URLs (out of scope → documented FN) |

Each candidate's framework semantics (e.g., what an unset vs `None` limit means in a given framework version) must be
verified from primary sources by Security Research before the rule is implemented; nothing above is a claim that
those semantics hold.

## 4. Distribution & adoption workstream (WS-E)

The competitive review concludes distribution is the hard part: the most-adopted tools are not the most rigorous.
Adoption work therefore starts in Phase 1, not Phase 9.

| Track | Phase introduced | Deliverable | Done when |
|-------|------------------|-------------|-----------|
| README | 1 (stub), 2 (real), each phase | 60-second quickstart, a screenshot of terminal + HTML report, rule list with **what each rule does not detect**, benchmark link, "clean ≠ secure" statement in the first screen | A new user can install and scan the sample repo with one copy-paste |
| Sample vulnerable repo | 2 | `examples/vulnerable-agent/` (synthetic, our licence) that triggers every shipped rule | `nexvul scan examples/vulnerable-agent` shows every rule |
| HTML report | 2 | Shareable offline report | Opens with networking disabled; passes XSS suite |
| GitHub Action | 6 (pre-release in 2 as a documented workflow snippet) | Marketplace Action with SARIF upload + `fail-on` | Works on a fresh public repo using only README instructions |
| pre-commit | 6 | `.pre-commit-hooks.yaml` with `id: nexvul` | `pre-commit try-repo` passes in CI |
| Docs site | 2 (rules + install), 6 (integrations), 9 (full) | Rule reference, FP guidance, SARIF, Action, pre-commit, security policy | Docs build in CI; links checked |
| Benchmark publication | 2 (seed), 7 (full) | Versioned report + methodology + raw data | Reproducible by one command |
| Comparisons | 7 | Feature comparison grounded in `docs/research/competitors/` plus measured runs where licences allow | Every claim cites a source or a reproducible run; no disparagement; competitors' own configs used |
| Launch | 9 | Release notes, a technical write-up on cross-file taint and the benchmark | Human approves any public post (agents may not post on the user's behalf) |
| Feedback loop | 2 onward | Issue templates for FP reports and missed detections; FP reports feed `fp-triage` | Every FP report triaged within the process in `.nexvul/README.md` |

Adoption metrics (to be tracked once public, not invented beforehand): installs, Action usage, FP reports per rule,
issues closed. No targets are set here; the human may set them.

## 5. Cross-phase dependency graph

```
P0 ─► P1 ─► P2 ─┬─► P3 ─┬─► P4 ─┐
                │       └─► P5 ─┼─► P7 ─► P8 ─► P9
                └─► P6 ─────────┘
WS-E (distribution) runs from P1 to P9.  WS-C harness exists from P1.
```

## 6. Top program risks

| Risk | Impact | Mitigation | Owner |
|------|--------|-----------|-------|
| Noisy rules destroy trust | Fatal for adoption | FP budget, held-out set, FP Hunter sign-off, "don't ship" is an allowed outcome | 01, 15, 17 |
| Cross-file taint harder than planned | Delays differentiator | Slice ships without it; flag-gated rollout; ADR before build | 14, 01 |
| Scanned repo attacks nexvul | Security incident | Phase 1 baseline hardening, Phase 8 red team, never-execute rule | 19, 16 |
| Benchmark overfitting / self-labelling | Credibility loss | Double review, held-out, external labellers, raw data published | 15 |
| Distribution fails despite quality | Project irrelevance | WS-E from Phase 1; Action + pre-commit + HTML report early | 20, 21 |
| Licence error in corpus | Legal | Allow-list, pinned refs not vendoring, §32.7 escalation | 15, 01 |
| Fake completion claims | Trust | Brief §33; phase reports cite commands run and artefacts | 01 |
