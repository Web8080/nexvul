# DEC-0003: Where the benchmark held-out set lives

| Field | Value |
|-------|-------|
| Status | accepted (Option A, repo created when first needed) |
| Decider | Human product owner, delegated to the Supervisor ("mk the calls") |
| Proposed by | 15 Benchmarking |
| Date proposed / decided | 2026-10-08 / 2026-10-08 |
| Escalation trigger (brief §32) | 1 (process architecture with materially different options) |
| Links | docs/benchmark-strategy.md §10; TASK-0014 |

## Context
An open-source repo cannot hide a held-out set from rule authors. Without real separation, held-out scores overstate
generalisation.

## Options considered
| Option | Pros | Cons |
|--------|------|------|
| A. Private repository owned by the human; evaluated by 15 Benchmarking only | Real separation | Extra repo to manage; not reproducible by outsiders until retired to dev |
| B. Local directory outside the repo on the owner's machine | Simple, fully local | Bus factor; backups |
| C. In-repo directory with "do not read" instruction | Zero overhead | Weak separation; must be disclosed in every report |

## Decision
**Option A: a private repository owned by the product owner.** Only the Benchmarking role evaluates it; rule
authors and rule-implementing agents see aggregate per-rule scores only.

- The private repo is **created when the first held-out case is written (Phase 2)**, not before. It is not created
  yet.
- Until then, and in every report that uses an interim set, state that held-out separation is the weaker
  "do not read" directory (option C).
- After each minor release the used set is retired into dev and published; a fresh set is written (benchmark
  strategy §10). Reports name the held-out generation used.
- Back it up: a private repo on one account is a single point of failure (the reason option B was rejected).

## Comments
