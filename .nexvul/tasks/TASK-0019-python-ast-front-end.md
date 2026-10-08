# TASK-0019: Python `ast` front end with resource guards

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | M |
| Owner | 04 Python Static Analysis |
| Reviewer(s) | 14 Data-Flow/Taint, 16 Adversarial Security |
| Depends on | TASK-0018, ADR-0001 accepted |
| Blocks | TASK-0024, Phase 2 rules |
| Links | docs/architecture.md §2, §9 |

## Acceptance criteria
- [ ] Parses with stdlib `ast` only (`ast.parse` — never `compile`+exec, never import)
- [ ] Recursion/size/time guards; parse failures become diagnostics, scan continues
- [ ] Each file parsed once; cache keyed by content hash (architecture §8.1) or explicitly deferred with a DEC
- [ ] Minimal IR needed for Phase 2 intra-procedural rules — no speculative IR
- [ ] Hypothesis fuzz: arbitrary bytes ⇒ no crash
- [ ] Reviewed: REV-NNNN
