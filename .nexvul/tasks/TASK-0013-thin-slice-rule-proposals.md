# TASK-0013: Rule proposals for thin-slice candidates S1–S3

| Field | Value |
|-------|-------|
| Status | ready |
| Phase | 0 (feeds Phase 2) |
| Size | M |
| Owner | 13 Detection Rule Engineer with 09 Memory (S1), 11 Cascading Failure (S2), 08 A2A / 07 MCP (S3) |
| Reviewer(s) | 01 Principal Supervisor, 17 False Positive Hunter, 16 Adversarial Security |
| Depends on | TASK-0001, TASK-0005, TASK-0006 |
| Blocks | Phase 2 |
| Created / Updated | 2026-10-08 / 2026-10-08 |
| Links | docs/roadmap.md §3, .nexvul/templates/rule-proposal.md |

## Goal
For each candidate, a completed rule proposal answering every brief §17 question — or a recorded decision to drop it.

## Acceptance criteria
- [ ] S1 (ASI06 HTTP fetch → vector-store/memory write, intra-procedural) proposal complete
- [ ] S2 (ASI08 explicitly unbounded iteration/recursion config) proposal complete, with framework semantics verified from primary sources per framework version
- [ ] S3 (ASI07 literal non-loopback `http://` MCP/A2A endpoint / auth explicitly absent) proposal complete
- [ ] Each lists look-alikes (→ negatives) and evasions (→ adversarial / known misses)
- [ ] Supervisor selects 2–3 for Phase 2 (REV-NNNN)
