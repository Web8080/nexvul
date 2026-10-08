# Task board

Index only; each task file is the source of truth. Status as of 2026-10-08 (written by Engineering Operations lead).
No task is `done`: `done` requires an approving REV by a non-owner, and no reviews have been recorded yet.

## Phase 0 — Research & foundations

| ID | Title | Owner | Status |
|----|-------|-------|--------|
| TASK-0001 | Attack-technique and ecosystem research | 02 | in_review |
| TASK-0002 | Competitive landscape research | 02 | in_review |
| TASK-0003 | Threat model | 01 | in_review |
| TASK-0004 | Architecture and ADR-0001 | 01 | in_review |
| TASK-0005 | Detection taxonomy | 13 | ready |
| TASK-0006 | OWASP mapping docs | 03 | ready |
| TASK-0007 | Product design | Design + 20 | in_progress |
| TASK-0008 | Roadmap | 15 | in_review |
| TASK-0009 | Benchmark strategy + schema | 15 | in_review |
| TASK-0010 | Test strategy | 18 | in_review |
| TASK-0011 | `.nexvul/` workspace | 15 | in_review |
| TASK-0012 | Agent role definitions + RACI | 15 | in_review |
| TASK-0013 | Thin-slice rule proposals S1–S3 | 13 | ready |
| TASK-0014 | Human decisions: FP budget, held-out location | 01 | blocked (human) |
| TASK-0015 | Phase 0 exit review | 01 | blocked |
| TASK-0016 | Fixture naming reconciliation | 18 | ready |

## Phase 1 — Foundation (backlog; starts only after TASK-0015 and human approval)

| ID | Title | Owner | Size |
|----|-------|-------|------|
| TASK-0017 | Package skeleton and CLI | 04 | S |
| TASK-0018 | Safe discovery and file loading | 04 | M |
| TASK-0019 | Python `ast` front end with guards | 04 | M |
| TASK-0020 | Finding model, JSON schema, fingerprints | 13 | S |
| TASK-0021 | Terminal + JSON reporters, goldens | 18 | S |
| TASK-0022 | Test framework scaffold, meta-tests | 18 | S |
| TASK-0023 | Malicious-input suite v0 | 16 | M |
| TASK-0024 | Rule plugin API and fixture runner | 13 | S |
| TASK-0025 | Benchmark harness v0 | 15 | M |
| TASK-0026 | Perf generator and baseline | 15 | S |
| TASK-0027 | CI pipeline for nexvul | 19 | M |
| TASK-0028 | OSS hygiene files, README stub | 20 | S |
| TASK-0029 | Real-world corpus onboarding | 15 | S |

## Open decisions
DEC-0001 (proposed) thin-slice sequencing · DEC-0002 (escalated) FP budget · DEC-0003 (escalated) held-out location.
