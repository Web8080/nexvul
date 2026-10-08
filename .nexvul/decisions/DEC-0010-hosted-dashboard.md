# DEC-0010: Hosted team dashboard (separate product, planned, not started)

| Field | Value |
|-------|-------|
| Status | accepted in principle; scoping only. No design or code started |
| Decider | Human product owner ("we would need this", 2026-10-08) |
| Escalation trigger | Brief §32 item 5 (feature that sends data off the machine). Human approval to plan it is now given; the design below still needs its own threat model before any build |
| Supersedes | The "separate product decision" note in DEC-0009 §4 |
| Links | DEC-0009; brief §2; docs/threat-model.md |

## Decision
Build a hosted team dashboard (accounts, scan history, trends, org-wide views) as a **separate product and
repository** that sits beside the scanner. The scanner and its local HTML report must keep working completely
without it.

## Data policy (default, may only be tightened without a new decision)
1. **Opt-in only.** Nothing is sent unless the user runs an explicit upload command (e.g. `nexvul push`) with a
   token they created. No upload from `scan`. No telemetry. Off by default, in CI and locally.
2. **Findings metadata only.** Rule ID, severity, confidence, ASI labels, file path, line, message text and
   completeness data. **No source code, snippets or secrets leave the machine by default.** Snippet upload, if ever
   added, is a separate explicit flag and a new decision.
3. Paths may reveal structure; offer a path-hashing or truncation option and show users exactly what would be
   sent (`--dry-run` prints the payload) before anything is uploaded.
4. Uploaded content is **untrusted input** to the hosted service (hostile filenames and messages: XSS, injection).
5. Self-hosting must stay possible; do not design anything that makes the open-source scanner depend on the
   hosted service.

## What the hosted product needs (scope, not designed)
Sign up, sign in, sign out, forgot/reset password, email verification, organisations and members with roles,
API tokens for CI, projects and repositories, scan history and trends, finding triage and suppression review,
settings, billing only if it becomes a paid product. Account screens, empty states and error states are Dave's to
design after the threat model.

## Order of work (nothing starts before the local slice ships)
1. Finish the local scanner thin slice and publish `0.1.0a1` (DEC-0001). The hosted product has nothing to show
   without scan output.
2. Hosted threat model and privacy design (tenancy isolation, token scoping, upload validation, data retention and
   deletion, breach impact). Reviewed before design or code.
3. Define the upload schema and `nexvul push` in the scanner (a small, auditable, opt-in client).
4. Dave: account flows and dashboard screens.
5. Build, then red-team.

## Open questions for the product owner (not blocking the scoping)
- Hosting and stack. The owner's other projects use Next.js with Clerk or Supabase; reusing them is likely,
  but each is a dependency with supply-chain and data-residency implications.
- Paid product, or free for open-source projects only? This affects billing, abuse handling and support load.
- Where the code lives (a new repo under the same GitHub account is the default).
- Data residency and retention promises you are willing to make publicly.

## Why not build it into this repo
A service with accounts has a different threat model, release process and on-call burden from a local CLI.
Mixing them would let a hosted-service bug weaken the scanner's local-first guarantee.
