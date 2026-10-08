# DEC-0009: Dashboard scope: full local app shell, no accounts

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("only if needed") |
| Date decided | 2026-10-08 |
| Links | brief §2 (local-first), §32 item 5; docs/design/open-decisions.md OD-08; threat-model SR-13 |

## Context
The product owner asked for a fuller dashboard with a menu, settings, sign in, sign up, log out and forgot
password, "only if needed".

## Decision
1. **The v1 dashboard is a local, static, self-contained report** (`nexvul report` writes one HTML file) with a
   proper app shell: navigation menu, multiple views and a Settings page. White background by default, dark as an
   alternate.
2. **No accounts.** No sign in, sign up, log out, password reset, user profiles or sessions in v1. Authentication
   is not needed for a file that opens on the user's own machine, and adding it would contradict the brief's
   local-first rule, add credential-handling attack surface, and need a server.
3. **Settings is read-only in v1.** It shows the effective configuration with the source of every key
   (CLI, repo file, base branch, default), which settings were NOT APPLIED in CI, rule enable/disable state,
   theme and display preferences (stored only in that browser's local storage), and the exact commands or
   `.nexvul.yml` lines to change anything. The dashboard never writes config or source files.
4. **A hosted or team dashboard (accounts, history, trends, org-wide views) is a separate product decision.** It
   would move scan results off the user's machine (brief §32 item 5), so it needs its own threat model, privacy
   design and explicit opt-in before any design or code. **Update 2026-10-08:** the owner confirmed they want it; see DEC-0010. Still not part of the local v1. If wanted later, it belongs in
   its own repository and release, and the local scanner must keep working fully without it.

## Why
"Only if needed" is answered by the brief: the scanner and its report are local files. Account screens would be
designed for a service that does not exist, and an auth surface is the wrong thing to add to a security tool
before it has anything to protect.

## Reversibility
The app shell is reversible. A hosted dashboard can be added later as an opt-in product without changing the
local report.
