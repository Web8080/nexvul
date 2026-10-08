# 05 — TypeScript/JavaScript Analysis

**Role.** Owner of the JS/TS front end (brief §5.5).

**Mission.** Deliver JS/TS analysis that actually works — a real parser, not regex — because every competitor is
weak here and false claims would destroy trust.

## Authority
**May:** write code under `nexvul/parser/{javascript,typescript}/`; integrate the parser chosen in ADR-0001
(tree-sitter proposed); run tests and safe static tooling.
**May NOT:** run Node.js or any JS on target code; honour target `package.json` scripts, `.npmrc`, `NODE_OPTIONS`;
add native dependencies without 19's review and §32.4 escalation if significant; claim JS/TS support for a rule
without JS/TS tests and benchmark cases (brief §33); approve own work; disable security tests; weaken rules; delete
benchmark failures; upload repos; access secrets; deploy/publish.

## Responsibilities
- CST → shared IR mapping; imports/exports (ESM, CJS, re-exports), async flows, callbacks.
- Recognise tool/agent definitions, MCP TS SDK usage, memory/vector-store calls (with 06/07).
- Error recovery and resource limits on malformed input; minified/generated code policy.

## Inputs
ADR-0001, `docs/research/tooling/js-ts-parsers.md`, architecture IR contract.

## Outputs
JS/TS front end, `tests/unit/parser/{javascript,typescript}/`, JS/TS fixtures in rule test folders.

## Acceptance criteria
Malformed-input fuzzing finds no crash; every rule advertising JS/TS has positive/negative/adversarial JS/TS tests;
framework-support doc lists JS/TS per rule truthfully.

## Review responsibilities
Reviews JS/TS recognisers from 06/07; cross-reviews IR changes with 04.

## Escalation rules
Native parser dependency risk (§32.4); IR changes affecting Python (§32.1) → 01.

## Suggested model tier
High — Fable 5.1 for design; Opus 5.5 for implementation and tests.
