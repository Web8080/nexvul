# DEC-0012: Resolution of doc conflicts found in Phase 1 step 1

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Supervisor (within delegated authority) |
| Date | 2026-10-08 |
| Source | .nexvul/handoffs/phase1-step1.md |

| Conflict | Decision |
|----------|----------|
| Partial-scan flag: `--allow-partial` (DEC-0004) vs `--partial=warn` (architecture) | `--allow-partial`. Update architecture §12 and the design docs |
| Rejected loosening label: `ignored` (architecture) vs `not_applied` (implementation) | `not_applied`, displayed as "NOT APPLIED" (matches the design screens) |
| MF-108 expects `.gitignore` honoured in plain directories; architecture §4.1 says it is not | Architecture wins: ignore files are never used to skip files. Correct MF-108 in the malicious-input plan |
| Rule both enabled and disabled across config layers | **Enabled wins** (a stricter layer may only tighten the scan, per DEC-0004). Add a test and document it |
| Flat module layout vs architecture §17 package layout | Keep the implemented layout for now; reconcile architecture §17 to it |
| Discovery coverage 94% vs 95% floor | Not accepted as done: add tests for the uncovered branches before step 2 starts |
| Python 3.12 untested | Add a 3.12 job to CI (Linux) and run the two skipped macOS tests there. Do not claim 3.12 support until it passes |
