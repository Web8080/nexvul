# TASK-0005: Detection taxonomy and rule ID allocation

| Field | Value |
|-------|-------|
| Status | ready |
| Phase | 0 |
| Size | M |
| Owner | 13 Detection Rule Engineer |
| Reviewer(s) | 01 Principal Supervisor, 03 OWASP Mapping, 02 Security Research |
| Depends on | TASK-0001 |
| Blocks | TASK-0013, Phase 2 |
| Created / Updated | 2026-10-08 / 2026-10-08 |
| Links | docs/detection-taxonomy.md (not present at time of writing), brief §16 |

## Goal
Turn brief §16 targets and research into a taxonomy of candidate detections with analysis type, confidence ceiling and priority; allocate NEX IDs only to approved candidates.

## Acceptance criteria
- [ ] Every brief §16 target listed with: analysis needed, expected precision risk, framework dependence, priority
- [ ] Thin-slice candidates S1–S3 (docs/roadmap.md §3) evaluated; at least two recommended
- [ ] ID policy: IDs never reused; withdrawn rules stay listed
- [ ] Reviewed: REV-NNNN
