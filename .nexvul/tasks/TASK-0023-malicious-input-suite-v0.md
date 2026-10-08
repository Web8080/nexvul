# TASK-0023: Malicious-input suite v0

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | M |
| Owner | 16 Adversarial Security |
| Reviewer(s) | 18 QA/Test, 19 DevSecOps |
| Depends on | TASK-0018, TASK-0022 |
| Blocks | Phase 1 exit |
| Links | docs/test-strategy.md §7, brief §19 |

## Acceptance criteria
- [ ] Generators (not committed giant files) for: giant file, huge line, deep nesting, too many files, symlink escape/loop, traversal/odd filenames, binary-as-.py, invalid encodings, archive present, malicious `.nexvul.yml`, prompt-injection comments
- [ ] Each case asserts: no crash, bounded time and memory, no access outside root, no network, no execution, clear diagnostic
- [ ] Any nexvul vulnerability found is filed in `.nexvul/security/` (not public)
- [ ] Reviewed: REV-NNNN
