# Handoff: Engineering Operations / Benchmarking

**Date:** 2026-10-08
**Author:** 15 Benchmarking (Engineering Operations lead)
**Status:** Delivered for review. Nothing here has been reviewed or approved yet. No scanner code was written, and nothing was committed.

## Delivered

| Path | Content |
|------|---------|
| `docs/roadmap.md` | Phases 0–9 (goal, deliverables, entry/exit, gates, risks, dependencies, S/M/L). The thin vertical slice comes first. Distribution workstream (§4). |
| `docs/benchmark-strategy.md` | Corpus layout, metadata schema, licence policy, never-execute rules, double-review labelling, metrics, **proposed** FP budget, CI gates, held-out set, verified candidate repos |
| `benchmarks/schema/example.schema.json` | JSON Schema 2020-12 for `case.yaml`. Validated with `jsonschema` in a scratch venv: the doc example passes and `../` paths are rejected |
| `docs/test-strategy.md` | Test pyramid, per-rule fixture folders, golden reporters, SARIF/HTML checks, Hypothesis, malicious-input suite, perf, coverage floors |
| `.nexvul/README.md` | Artefact protocol, ID schemes, status lifecycle, review independence |
| `.nexvul/templates/` | task, decision, review (§30 checklist), rule-proposal (§17), fp-triage, adversarial-report, phase-report |
| `.nexvul/tasks/` | TASK-0001…0016 (Phase 0, with statuses), TASK-0017…0029 (Phase 1 backlog), README index |
| `.nexvul/decisions/` | DEC-0001 thin-slice sequencing (proposed), DEC-0002 FP budget (escalated), DEC-0003 held-out location (escalated) |
| `.nexvul/agents/` | 21 role files + README (org chart, RACI, model tiers) |

## Decisions needed from the human
1. **DEC-0002:** approve or amend the FP budget (benchmark-strategy §8.3). Phase 2 cannot exit until this is decided.
2. **DEC-0003:** decide where the held-out set lives.
3. Decide whether the AutoGPT MIT portion may be referenced by path (it is mixed-licence with Polyform Shield).
4. Approve the sequencing change: SARIF, HTML, the harness and a pre-release move earlier (DEC-0001). The Supervisor can decide this, and the human is informed.

## Issues found for other owners
- **Fixture naming (TASK-0016):** the example in `docs/architecture.md` §6.4 is named `test_positive_001.py`. pytest would collect and **execute** it, which breaks brief §2. Rename it to `case_<nnn>_<slug>.py` and add a meta-test. I did not edit architecture.md.
- `docs/detection-taxonomy.md` and `docs/owasp/` did not exist when this was written (TASK-0005, TASK-0006).
- Licence notes: GitHub reports `microsoft/autogen` as CC-BY-4.0, which covers the docs only. The code is MIT under `LICENSE-CODE`. MCP `servers` and `typescript-sdk` are mixed MIT/Apache-2.0. `crewAI-examples` has no licence, so it is excluded.

## Caveats
- Repo licences and HEAD SHAs were observed on 2026-10-08 through the GitHub API and `git ls-remote`. Re-verify them when each repo is onboarded. None of these repos has been scanned.
- All thresholds (FP budget, perf regression %, coverage floors) are proposals. None are measured facts.
- Thin-slice candidates S1–S3 are not rules yet. The framework semantics behind S2 (iteration-limit defaults) are unverified.
