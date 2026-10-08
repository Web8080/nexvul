# TASK-0024: Rule plugin API and fixture runner

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | S |
| Owner | 13 Detection Rule Engineer |
| Reviewer(s) | 18 QA/Test, 14 Data-Flow/Taint |
| Depends on | TASK-0019, TASK-0020, TASK-0022 |
| Blocks | Phase 2 rules |
| Links | docs/architecture.md §6, docs/test-strategy.md §4 |

## Acceptance criteria
- [ ] Rule registration per architecture §6.3; rules independently testable
- [ ] Generic fixture runner reads `# nexvul-expect:`, `# nexvul-expect-not:`, `# nexvul-known-miss:` annotations
- [ ] A no-op demo rule with all four fixture folders proves the runner (removed or marked internal before release)
- [ ] Reviewed: REV-NNNN
