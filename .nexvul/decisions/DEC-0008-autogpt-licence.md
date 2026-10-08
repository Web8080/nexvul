# DEC-0008: AutoGPT excluded from the benchmark corpus

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("mk the calls") |
| Proposed by | 15 Benchmarking (docs/benchmark-strategy.md §11) |
| Date decided | 2026-10-08 |
| Escalation trigger | Brief §32 item 7 (licensing unclear) |

## Context
AutoGPT is a mixed-licence repository: part MIT, part Polyform. The benchmarking agent asked whether a
path-restricted use of the MIT part was acceptable.

## Decision
**Excluded entirely.** No code, files or snippets from AutoGPT enter the corpus, vendored or by pinned reference.

## Why
Brief §32 says stop when licensing is unclear. A path-restricted carve-out depends on getting the licence
boundary exactly right on every commit, and nexvul gains little from one more large repo. Wrong licensing in a
public security project costs more than the extra data is worth.

## Revisit
Only with an explicit written licence boundary for specific paths, or a replacement project with a plain
permissive licence. Applies the same rule to any other mixed-licence candidate: out unless every included path is
clearly permissive.
