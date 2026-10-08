# DEC-0001: Ship a thin vertical slice before breadth

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | 01 Principal Supervisor; human product owner delegated the call ("mk the calls") |
| Proposed by | 15 Benchmarking / Engineering Operations lead |
| Consulted | 13 Detection Rule Engineer, 18 QA, 20 Documentation, 21 Release |
| Date proposed / decided | 2026-10-08 / 2026-10-08 |
| Escalation trigger (brief §32) | none — sequencing change within the brief's scope; no phase or deliverable removed |
| ADR | not architectural |
| Links | docs/roadmap.md §0, §3; TASK-0008 |

## Context
Brief §27 orders phases breadth-first; SARIF arrives in Phase 6 and benchmarking in Phase 7. The competitive review
(`docs/research/competitors/README.md`) shows trust (measured precision), shareable output (HTML) and fully-local
operation are achievable differentiators, and that distribution is the hard part.

## Options considered
| Option | Pros | Cons |
|--------|------|------|
| A. Literal §27 order | Matches brief text | Nothing usable until Phase 9; rules built before the harness that measures them |
| B. Thin slice first (Python, 2–3 rules, terminal/JSON/SARIF/HTML, seed benchmark, pre-release) | Early evidence and feedback; harness exists before breadth | Some integration work earlier; requires discipline to keep slice thin |

## Decision (accepted)
Option B. Keep phase names/numbers; pull SARIF, HTML report, benchmark harness, baseline hardening and pre-release
packaging forward as listed in roadmap §0. Publishing any pre-release still requires Release + Supervisor approval.

## Consequences
Phase 2 exit becomes the first public-quality milestone. Phase 6 shrinks to Action/pre-commit/baseline.

## Reversibility
Fully reversible until a pre-release is published.

## Comments

Accepted 2026-10-08. Publishing any pre-release still needs Release Engineer and Supervisor approval (brief §21).
