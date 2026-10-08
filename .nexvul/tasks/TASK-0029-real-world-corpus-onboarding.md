# TASK-0029: Onboard first real-world corpus projects (pinned refs)

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 (used from Phase 2) |
| Size | S |
| Owner | 15 Benchmarking |
| Reviewer(s) | 01 Principal Supervisor (licence), 19 DevSecOps (safe fetch) |
| Depends on | TASK-0025 |
| Blocks | Phase 2 real-world triage |
| Links | docs/benchmark-strategy.md §5–6, §11 |

## Goal
Add `benchmarks/real_world/<slug>/case.yaml` for ~5 allow-listed projects relevant to the slice rules (suggested: langchain, langgraph, gpt-researcher, mem0, a2a-samples), pinned to full SHAs.

## Acceptance criteria
- [ ] Licence re-verified at onboarding (root + subdirectory licence files), recorded in case.yaml
- [ ] Full 40-hex SHA pinned; no source vendored
- [ ] Fetch script: hooks disabled, no submodules, `GIT_LFS_SKIP_SMUDGE=1`, fetch-by-SHA + verify, cache outside repo, no installs
- [ ] Any ambiguous licence escalated (brief §32.7), not decided by an agent
- [ ] Reviewed: REV-NNNN
