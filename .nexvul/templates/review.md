# REV-NNNN: Review of <artefact> at <revision>

| Field | Value |
|-------|-------|
| Status | open \| approved \| changes_requested \| rejected |
| Reviewer | NN <role> |
| Author of artefact | NN <role> (must differ from reviewer) |
| Artefact | path(s) + git SHA or file hash reviewed |
| Type | rule \| code \| doc \| benchmark-label \| ci/release \| phase-exit |
| Date | YYYY-MM-DD |
| Links | TASK-…, DEC-…, FND-… |

## Summary verdict
One paragraph. If rejecting, say what would change the verdict.

## Brief §30 quality-gate checklist
Mark each **Pass / Fail / N/A (reason)** and cite evidence. Any critical Fail ⇒ not approved.

| # | Gate | Result | Evidence (path, test name, command, report) |
|---|------|--------|---------------------------------------------|
| G1 | Requirement understood (matches task/brief; no silent scope change) | | |
| G2 | Threat model considered (docs/threat-model.md entries referenced; hostile-input impact) | | |
| G3 | Architecture reviewed (consistent with docs/architecture.md / ADRs) | | |
| G4 | Tests exist and ran in CI on this revision | | |
| G5 | Positive, negative **and** adversarial cases present | | |
| G6 | False positives investigated (FP-triage FND linked) | | |
| G7 | Performance measured (report path) | | |
| G8 | Documentation updated (rule doc, README, CHANGELOG as relevant) | | |
| G9 | OWASP mapping present and defensible (no claim of proven exploitation) | | |
| G10 | Security reviewed (never executes scanned code; no network; output escaping; limits) | | |

## Additional checks
- [ ] No test deleted, skipped, `xfail`-ed or loosened without an approving REV (brief §21)
- [ ] No benchmark case removed or relabelled to improve metrics (brief §23)
- [ ] Claims are evidenced; nothing says "implemented/tested/compliant" without proof (brief §33)
- [ ] For rules: every brief §17 question answered in the rule proposal
- [ ] For rules: messages are specific (source and sink named — brief §10)
- [ ] For dependencies: supply-chain review done; escalate if significant (brief §32.4)
- [ ] Clean-scan disclaimer intact wherever results are presented

## Findings
| # | Severity (blocker/major/minor/nit) | Location | Issue | Required change |
|---|-----------------------------------|----------|-------|-----------------|

## Comments
