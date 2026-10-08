# TASK-0018: Safe repository discovery and file loading

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | M |
| Owner | 04 Python Static Analysis |
| Reviewer(s) | 16 Adversarial Security (red-team before done), 18 QA/Test |
| Depends on | TASK-0017, TASK-0003 |
| Blocks | TASK-0019, TASK-0023 |
| Links | docs/architecture.md §8–9, docs/test-strategy.md §7, brief §2 |

## Acceptance criteria
- [ ] Never follows symlinks outside root; detects loops; deterministic ordering
- [ ] Limits enforced: per-file size, file count (`analysis.max_files`), path depth; binary detection; encoding handling
- [ ] Excludes from `.nexvul.yml` cannot escape the root
- [ ] Archives never extracted
- [ ] Property tests: no yielded path outside root (Hypothesis)
- [ ] Coverage ≥ 95% line / 90% branch (test-strategy §9)
- [ ] Adversarial report FND-NNNN with no open critical/high
- [ ] Reviewed: REV-NNNN
