# DEC-0005: OWASP labelling of the ASI09 and ASI10 rules

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("make the call") |
| Proposed by | Security Research (docs/research/open-questions-security.md Q1, Q2) |
| Date decided | 2026-10-08 |
| Trigger | Brief §32 item 3 (controversial interpretation of OWASP guidance) |

## Context
The brief groups "destructive or financial tool without approval" under ASI09 and "shell + network, broad
filesystem, no limits" under ASI10. Checked against the OWASP 2026 document, ASI09 is about humans over-trusting
agents and ASI10 about agent behaviour drifting. The capability and missing-approval rules fit ASI02 (tool
misuse), ASI03 (identity and privilege abuse) and ASI05 better, though OWASP's own examples also support ASI09 for
missing confirmation.

## Decision
Findings carry **multiple OWASP labels**: the closest-fit category first, and the brief's ASI09 or ASI10 label
retained where OWASP's text supports it. Rule titles and messages are worded as what the code shows
("destructive tool registered without an approval gate", "agent has shell and network with no containment"),
not as proof of rogue behaviour or of a trust-exploitation attack. The rule-to-ASI table in docs/owasp/mapping.md
is authoritative; changing a label needs a mapping update and a changelog note.
The HTML report and SARIF tags list all labels; the primary label drives grouping.

## Reversibility
Labels are metadata and can change between minor versions with a changelog entry.
