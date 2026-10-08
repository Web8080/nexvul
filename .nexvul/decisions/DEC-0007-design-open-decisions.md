# DEC-0007: Design open decisions OD-01 to OD-16

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("make the call") |
| Proposed by | Design (Dave), docs/design/open-decisions.md |
| Date decided | 2026-10-08 |

**All sixteen recommendations in `docs/design/open-decisions.md` are accepted as written.** Summary:

| ID | Outcome |
|----|---------|
| OD-01 | Repo config in CI: weakening keys only from the base ref or explicit input (same as DEC-0004 §1) |
| OD-02 | ASI labels: ordered multi-label, ASI09/ASI10 always present where OWASP's text supports it (DEC-0005) |
| OD-03 | Suppression justification optional locally, required in CI (DEC-0004 §2) |
| OD-04 | Suppression syntax is `# nexvul: ignore[NEX006] -- reason` (and `//` form). Public and hard to change later |
| OD-05 | Nothing to analyse exits 3, never "No findings" |
| OD-06 | Exit codes 0/1/2/3/4 plus 130/143. Precedence 2 > 4 > 3 > 1 > 0. Partial scan exits 3 locally and in CI |
| OD-07 | GitHub shows the rule's default severity; the finding's effective severity leads the message text. Verify with contract ask CA-3 |
| OD-08 | HTML report ships in the Phase 2 thin slice. SR-13 (XSS/CSP/no-network suite) is a release blocker for it |
| OD-09 | No workflow-command annotations from the Action in v1 |
| OD-10 | Brand deviations DV-1 to DV-12 approved (no green, no OWASP-coverage tile, trace mark instead of shield, taxonomy rule IDs) |
| OD-11 | Canonical repo owner/URL still open; decide before the first release. Currently github.com/Web8080/nexvul |
| OD-12 | `nexvul init` deferred |
| OD-13 | Info-level findings are not uploaded to SARIF; shown in the report and `--verbose` |
| OD-14 | A staged file that fails to parse blocks the commit (exit 3); user config can downgrade |
| OD-15 | Default `fail-on` is `high` |
| OD-16 | Keep `--explain` on `scan` as well as `nexvul explain` |

## Follow-through
- The README hero mock-up was regenerated on 2026-10-08 to apply DV-1..DV-11 where practical (taxonomy rule IDs,
  no green, no coverage tile, trace mark, softer wording). It must be regenerated from the real report template
  once that exists (design-system §10); do not keep hand-editing it.
- The exit-code contract (OD-06) matches architecture §12 and the DEC-0004 partial-scan decision.
- OD-11 remains the one open item from this list.
