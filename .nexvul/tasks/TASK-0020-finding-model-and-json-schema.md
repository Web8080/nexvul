# TASK-0020: Finding model, JSON schema v0, fingerprints

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | S |
| Owner | 13 Detection Rule Engineer |
| Reviewer(s) | 18 QA/Test, 19 DevSecOps (SARIF fingerprint compatibility) |
| Depends on | TASK-0017 |
| Blocks | TASK-0021, TASK-0025 |
| Links | brief §10, docs/architecture.md §7 |

## Acceptance criteria
- [ ] Model matches brief §10 fields plus architecture §7 additions; versioned JSON Schema committed
- [ ] Fingerprints stable under whitespace/comment edits; distinct for distinct flows (property tests)
- [ ] Message-specificity check helper (source + sink named) available to rule tests
- [ ] Reviewed: REV-NNNN
