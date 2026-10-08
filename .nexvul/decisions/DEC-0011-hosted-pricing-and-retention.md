# DEC-0011: Hosted dashboard: free for open-source, and the retention and deletion promises

| Field | Value |
|-------|-------|
| Status | accepted as the design target. The public wording needs legal and privacy review before launch |
| Decider | Human product owner, delegated to the Supervisor ("make the call") |
| Date decided | 2026-10-08 |
| Links | DEC-0010; brief §2, §32 item 5 |

These are product commitments to design and build toward. They are not legal advice. Do not publish them as
promises until a privacy policy has been reviewed (the owner is in the UK, so UK GDPR applies, and users in the EU
bring EU GDPR). Promise only what the system actually does; every promise below needs a test.

## 1. Pricing and eligibility
**Free for open-source projects only.** No paid tier, no billing code, no card handling in v1.
- Eligible: a repository that is **public on GitHub** and carries an OSI-approved licence. Eligibility is checked
  when a project is created and rechecked on a schedule; a repo that goes private or loses its licence stops
  accepting uploads (read access and export remain for 30 days).
- **Private repositories are not supported.** This also keeps the data policy simple: uploaded paths and rule
  results describe code that is already public.
- Abuse limits keep the free tier affordable: payload size cap, uploads per project per day, projects per
  account. Exact numbers are set after measuring real payloads (Phase 2). Unannounced cuts to limits are not
  acceptable; changes are announced in the changelog.
- If paid plans are ever added, that is a new decision and cannot reduce what free projects were promised.

## 2. What is collected (restating DEC-0010)
Findings metadata only (rule, severity, confidence, ASI labels, path, line, message text, completeness data), plus
the account data needed to sign in (email, GitHub identity, organisation membership). **No source code or
snippets.** No analytics or ad trackers on the dashboard.

## 3. Retention (design targets)
| Data | Kept for | Notes |
|------|----------|-------|
| Detailed findings per scan (paths, lines, messages) | **90 days** after the scan, then deleted | Enough for triage and recent history |
| Aggregate trend data (counts by severity, rule and date; no paths or messages) | **24 months** | Derived from findings; contains no file names |
| Active suppression and triage decisions | Life of the project | These are the team's own records |
| API tokens | Default expiry **90 days**; revoked tokens are deleted immediately | Stored hashed only; shown once |
| Access and audit logs | **30 days** (security audit events for the account: 12 months) | Contain IPs; kept short |
| Account data (email, identity) | Until the account is deleted | See §4 |
| Inactive projects | Warning after **180 days** with no uploads; project and its data deleted after **12 months** | Owners can export first |

## 4. Deletion promises
- **Delete a scan, a project or an account yourself**, in the product and by API, with no support ticket.
- Primary data is removed **within 7 days** of a delete request; copies in backups expire **within 35 days**
  (backup rotation is 30 days; the extra days are slack). The product states both numbers.
- Account deletion removes memberships and tokens immediately and personal data within the same 7 days. Records
  in shared projects (a triage comment, for example) are attributed to "deleted user", not kept under the name.
- **Export** before deletion: findings and triage decisions in SARIF and JSON.
- A **deletion request is verified** (signed-in owner or verified email); deletions are logged without the content.
- No sale or sharing of data. No use of uploaded data to train models.
- **Breach notice:** affected users are told within **72 hours** of a confirmed breach affecting their data
  (aligns with UK/EU GDPR timing for the regulator), with what was exposed.
- Self-hosting stays possible: users who do not want any hosted copy keep full local functionality.

## 5. Consequences for design and build
- The data model carries `deleted_at`, retention class and expiry per record; a scheduled job enforces §3 and is
  tested (a test must prove that 90-day-old detail is gone and the aggregate remains).
- Uploads are untrusted input (DEC-0010). Backups, logs and exports are in the deletion scope; the threat model
  for the hosted service must cover them.
- The eligibility check needs GitHub API access; design it so it stores no GitHub token longer than the check.
- A privacy policy, subprocessor list and data-processing terms are launch blockers, along with the legal review.

## Open
- Real numbers for payload, upload and project quotas (after measuring).
- Whether to offer a public, read-only project page and badges (default off; per-project opt-in).
- Where the service is hosted (UK or EU region preferred for a UK/EU user base).
