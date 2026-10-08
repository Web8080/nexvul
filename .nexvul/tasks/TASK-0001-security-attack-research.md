# TASK-0001: Attack-technique and ecosystem research

| Field | Value |
|-------|-------|
| Status | in_review |
| Phase | 0 |
| Size | L |
| Owner | 02 Security Research |
| Reviewer(s) | 01 Principal Supervisor, 03 OWASP Mapping |
| Depends on | none |
| Blocks | TASK-0003, TASK-0005, TASK-0006, TASK-0013 |
| Created / Updated | 2026-10-08 / 2026-10-08 |
| Links | docs/research/attack-techniques/, docs/research/frameworks/, docs/research/protocols/, docs/research/tooling/, docs/research/owasp-agentic-top10-2026.md |

## Goal
Document how agent systems actually fail, per technique, with the brief §5.2 fields, so rules are grounded in evidence.

## Outputs
`docs/research/attack-techniques/*.md` (one per technique in brief §5.2), framework/protocol/tooling notes.

## Acceptance criteria
- [ ] Every technique in brief §5.2 has a file with: attack, preconditions, attack_flow, observable_code_patterns, possible_static_signals, false_positive_cases, false_negative_cases, framework_examples, owasp_mapping, confidence
- [ ] External claims cite sources or are marked unverified
- [ ] Framework research covers LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP, A2A (gaps listed)
- [ ] Reviewed: REV-NNNN approved by 01 and 03

## Log
- 2026-10-08 15-EngOps: files observed present under docs/research/; review not yet performed.
