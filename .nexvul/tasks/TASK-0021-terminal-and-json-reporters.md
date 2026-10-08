# TASK-0021: Terminal and JSON reporters with golden tests

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | S |
| Owner | 18 QA/Test (implementation) with 20 Documentation (wording) |
| Reviewer(s) | 16 Adversarial (output injection), 01 Principal Supervisor |
| Depends on | TASK-0020, TASK-0007 |
| Blocks | Phase 2 SARIF/HTML |
| Links | brief §24–25, docs/test-strategy.md §5 |

## Acceptance criteria
- [ ] Terminal header per brief §25; findings grouped by severity; `NO_COLOR` honoured
- [ ] Clean-scan output states that a clean result does not prove the application is secure
- [ ] Control characters / ANSI escapes from scanned filenames and snippets are neutralised in terminal output
- [ ] Golden tests for empty, single, many, unicode, long-message cases
- [ ] JSON validated against schema in tests
- [ ] Reviewed: REV-NNNN
