# DEC-0015: nexvul is licensed under Apache-2.0

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("make every call") |
| Date | 2026-10-13 |

**Decision:** Apache License 2.0 for the scanner, its docs and the original synthetic benchmark cases.

**Why:** permissive so teams can adopt it in CI without legal friction; an explicit patent grant; the common choice
for security tooling (Agentic Radar, Snyk Agent-Scan and Cisco's MCP scanner use Apache-2.0); contributions carry
an express licence grant. MIT was the alternative (shorter, no patent grant).

**Consequences:**
- Third-party material in the benchmark corpus keeps its own licence and is recorded per case (brief section 22).
- A hosted dashboard (DEC-0010) is a separate repo and may use a different licence; the scanner stays Apache-2.0.
- Contributors license their contributions under Apache-2.0 (state this in CONTRIBUTING.md when it is written).

**Reversibility:** can be changed for future versions only; copies already published stay under Apache-2.0.
