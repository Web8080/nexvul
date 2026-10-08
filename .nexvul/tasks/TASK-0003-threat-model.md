# TASK-0003: Threat model for nexvul and for scanned systems

| Field | Value |
|-------|-------|
| Status | in_review |
| Phase | 0 |
| Size | M |
| Owner | 01 Principal Supervisor (with 02 Security Research, 19 DevSecOps) |
| Reviewer(s) | 16 Adversarial Security |
| Depends on | TASK-0001 |
| Blocks | TASK-0004, Phase 1 |
| Created / Updated | 2026-10-08 / 2026-10-08 |
| Links | docs/threat-model.md, docs/security-model.md |

## Goal
Enumerate threats to nexvul itself (hostile repositories, hostile config, output injection, supply chain) and the agent-system threats nexvul detects.

## Acceptance criteria
- [ ] Every brief §2 hostile-input class has a threat entry and a planned control
- [ ] Each control maps to a test category in docs/test-strategy.md §7
- [ ] Output-injection threats for SARIF and HTML covered
- [ ] Reviewed: REV-NNNN by 16

## Log
- 2026-10-08 15-EngOps: docs/threat-model.md and docs/security-model.md observed present; not reviewed by EngOps.
