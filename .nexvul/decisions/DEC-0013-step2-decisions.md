# DEC-0013: Step 2 decisions

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Supervisor (within delegated authority) |
| Date | 2026-10-13 |
| Source | .nexvul/handoffs/phase1-step2.md |

1. **`parser_unavailable` completeness reason: accepted.** It marks the scan partial (exit 3). Never treat an
   unavailable parser as "nothing to find".
2. **Unenforced resource limits are shown, not hidden.** When a limit is not enforced on the current OS (for
   example the memory cap on macOS), the scan-completeness block lists it as `limit not enforced: memory (macOS)`
   on every scan, and `nexvul doctor` explains it. It does not by itself make the scan partial, because the
   file-size and nesting caps still apply.
3. **Acknowledged gaps, to close before release:** run the suite on Linux (CI already does for 3.12 and 3.13);
   replace the simulated worker-crash test with a real crash input in Phase 8; name binding ignores control flow
   (documented precision limit, recorded as a false-negative risk).
