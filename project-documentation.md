# nexvul: Project Documentation

Living record of the project: what it is, where it stands, what was decided, what is open, and how to continue.
Update this file whenever a phase closes or a decision changes. Last updated: 2026-10-08.

## 1. What this is

**nexvul** is an open-source, local-first **static** security scanner for AI-agent applications (Python and
TypeScript/JavaScript agent code, prompts, tool definitions, MCP configs, workflow definitions). Findings map to the
OWASP Top 10 for Agentic Applications 2026, with first focus on ASI06 to ASI10.

Ground rules that override everything else:
- The scanned code is untrusted. Never execute, import or instantiate it.
- Local-first: no telemetry, no source upload, no network needed to scan.
- A clean result is never proof of security. Every output carries a scan-completeness block.
- Precision over volume. A rule ships only after its false-positive behaviour is measured.
- Never claim "implemented", "tested" or "supported" unless it is true. Never invent numbers or CVEs.

The original build brief is saved at [docs/brief/master-brief.md](docs/brief/master-brief.md). It is the source of truth.
(The brief's working title "AgentLatch" was replaced by **nexvul**.)

## 2. Where things live

| Item | Location |
|------|----------|
| GitHub repo (public) | https://github.com/Web8080/nexvul (owner is the `Web8080` account, not `web808`) |
| Local checkout | `/Users/innovations/nexvul` |
| Default branch | `main`, pushed after each work wave |
| PyPI / npm / GitHub handle | `nexvul` was free on PyPI, npm and GitHub on 2026-10-08. A quick lookup, not independently verified. Re-check before the first release |

## 3. Current status

**Phase 0 (research and design): first drafts complete, not yet reviewed. No scanner code exists.**

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Research, threat model, architecture, taxonomy, design | Drafts done, review pending |
| 1 to 9 | Foundation, rules, taint, frameworks, JS/TS, integrations, benchmarks, hardening, release | Not started |

Nothing has been published to any package index or marketplace. The README hero image is a **design mock-up with
sample data**, labelled as such.

## 4. Repository map

| Path | Contents |
|------|----------|
| `README.md` | Public landing page, mock-up screenshot first |
| `docs/brief/master-brief.md` | The full build brief |
| `docs/research/` | OWASP Agentic Top 10 notes, attack techniques, competitors, frameworks, protocols (MCP, A2A), tooling (Semgrep, CodeQL, Bandit, SARIF, GitHub Actions, JS/TS parsers) |
| `docs/threat-model.md`, `docs/security-model.md` | Threats against nexvul itself (T-01..T-30) and requirements (SR-01..SR-30); user-facing security model |
| `docs/architecture.md` (rev 2) | Pipeline, IR, taint design, worker isolation, cache, exit codes |
| `docs/adr/0001-...` | Parser and static-analysis architecture. Status: **Proposed** |
| `docs/detection-taxonomy.md` | Detection classes and candidate rules NEX001 to NEX025 (all "design only") |
| `docs/owasp/` | Rule-to-ASI mapping with CWE and limitations |
| `docs/roadmap.md`, `docs/benchmark-strategy.md`, `docs/test-strategy.md` | Plan, corpus and metrics, test approach |
| `docs/design/` | Journeys, screen inventory, terminal mock-ups, GitHub/Action UX, design system, brand, open decisions |
| `docs/environments.md` | dev / staging / prod release channels |
| `.nexvul/` | Engineering workspace: tasks, decisions, agent roles, templates, handoffs, security test plan |
| `assets/` | Report mock-up (`report-preview.html`) and screenshots |
| `benchmarks/schema/` | Corpus metadata schema. The corpus itself is not built yet |

## 5. Decisions made

Recorded in `.nexvul/decisions/`. The product owner delegated these calls ("make the call") on 2026-10-08.

| ID | Decision |
|----|----------|
| DEC-0002 | False-positive budget approved with amendments: a threshold is enforced only once a rule has 20 or more labelled cases; always report raw TP/FP/FN counts with an interval; zero high-confidence FPs on `safe/` is a hard gate |
| DEC-0004 | Repo config in CI may only tighten the scan (loosening only from the base branch). Inline suppressions need a rule ID and a reason in CI, and PR-added ones are listed. A partial scan fails CI by default. No rule plugins until after 1.0 |
| DEC-0005 | ASI09/ASI10 rules get ordered multi-labels (closest-fit OWASP category first, brief's label kept where OWASP's text supports it) |
| DEC-0006 | Staging publishes only the `@staging` tag and a TestPyPI rc; Marketplace listing only from prod. No Docker image for 1.0. Signing and attestations required from the first release candidate |
| DEC-0001 | Thin vertical slice first: Python-only, 2 to 3 rules, terminal + JSON + SARIF + HTML, seed benchmark, pre-release; breadth after |
| DEC-0003 | Held-out benchmark set in a private repo owned by the product owner, created in Phase 2; weaker interim protection disclosed in reports |
| DEC-0008 | AutoGPT excluded from the corpus entirely (mixed licence) |
| DEC-0007 | All 16 design open decisions accepted: suppression syntax `# nexvul: ignore[NEX006] -- reason`; exit codes 0/1/2/3/4 (precedence 2>4>3>1>0); nothing-to-analyse exits 3; HTML report ships in the thin slice; default `fail-on: high` |

Environments (configured on GitHub): `dev` (any branch), `staging` (`main` only), `prod` (`v*` tags only, reviewer required).
No release workflow exists yet because there is no package to build.

## 6. Open items needing the product owner

1. **OD-11**: canonical GitHub owner and URL before the first release.
2. **ADR-0001**: still Proposed. It includes the JS/TS parser choice, which has supply-chain implications.
3. **Licence for nexvul itself**: not chosen. Until a LICENSE file exists, no rights are granted. MIT or Apache-2.0 suggested.
4. **Held-out repo**: the private repo (DEC-0003) is created when the first held-out case is written. Back it up.

Closed on 2026-10-08: DEC-0001 (thin slice first, accepted), DEC-0003 (private held-out repo, created when first
needed), DEC-0008 (AutoGPT excluded entirely).

## 7. Differentiation

Existing tools (agentic-top10-scan, Agent Audit, agentic-semgrep-rules, Agentic Radar, Snyk Agent-Scan, Cisco MCP
Scanner) are profiled in `docs/research/competitors/`. Gaps found in all of them, which are nexvul's goals and not
yet shipped features:
- Cross-file taint analysis, aimed first at ASI06 memory and context poisoning
- Working JS/TS parsing with a real parser
- A self-contained HTML report alongside terminal, JSON and SARIF
- Fully local operation, with no API key or LLM calls

Distribution is the harder problem: free scanners do not attract users by existing. Adoption workstream is in `docs/roadmap.md`.

## 8. Known caveats (be honest about these)

- Everything in Phase 0 is agent-written and has had only cross-checks between agents. No independent review yet.
- Many citations were not link-checked. The CVE and statistics claims in the nine earlier attack-technique files are unverified.
- Names marked `UNVERIFIED` in `docs/research/frameworks/` must be confirmed before any recogniser relies on them.
- LangGraph's default recursion limit varies by version (25 up to 1.0.5, 10000 from 1.0.6); severity must use the lockfile version.
- Microsoft Agent Framework, Google ADK, Pydantic AI and Semantic Kernel are not researched yet.
- NEX004 and NEX023 are not ready (need models that do not exist). The ASI10 capability weights are uncalibrated.
- The mock-up's findings are invented sample data. The benchmark thresholds are proposals, not measurements.
- `docs/threat-model.md` sections 1 and 9 still describe the first architecture draft.
- The brief's section numbering skips from 19 to 21 in the original paste; section 20 was restored from §2.

## 9. Proposed next steps

1. Phase 0 review: Supervisor reviews each document, link-checks citations, fixes the stale threat-model sections, and closes ADR-0001.
2. Get answers on section 6.
3. Phase 1 (thin slice): package skeleton and config loader, file discovery with self-protection limits, Python parser and IR with worker isolation, reporters, malicious-input suite in CI.
4. Phase 2: NEX001 (external content to persistent memory), NEX007 (MCP without auth), NEX014 (iteration limit), each with benchmark cases and the 20-case minimum.
5. Release `0.1.0a1` to staging, measure, publish the numbers, then expand.

## 10. How the work is run

- The main session plans and delegates. Specialist agents (research, architecture, threat modelling, design, benchmarks) write artefacts into the repo. Each agent saves one file at a time so a usage-limit cut-off loses little.
- Several agent runs failed on usage limits earlier and were re-dispatched in smaller batches. If it happens again, re-dispatch only the missing files.
- Handoff notes from each agent are in `.nexvul/handoffs/`. Read those before re-running an area.
- Commits are pushed to `main` after each wave. Commit messages end with a co-author trailer.
- Agents may not publish packages, deploy, weaken a rule to pass tests, delete benchmark failures, or execute scanned code.
