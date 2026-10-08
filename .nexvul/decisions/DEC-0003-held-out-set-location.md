# DEC-0003: Where the benchmark held-out set lives

| Field | Value |
|-------|-------|
| Status | escalated |
| Decider | Human product owner |
| Proposed by | 15 Benchmarking |
| Date proposed / decided | 2026-10-08 / — |
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
Pending. Interim: option C with disclosure, per benchmark-strategy §10.

## Comments
