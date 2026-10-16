# DEC-0016: Step 5a decisions (SARIF)

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Supervisor (within delegated authority) |
| Date | 2026-10-16 |

1. **OD-11 decided:** the canonical repository is `github.com/Web8080/nexvul`. All fixed links use it. If the
   project moves to an organisation later, change the one constant `REPO_URL` and regenerate the goldens.
2. **Columns:** findings carry UTF-8 byte columns; SARIF declares `utf16CodeUnits`, so columns are exact only on
   ASCII lines. The limit is stated in the SARIF run properties. Fix (compute UTF-16 columns in the worker) is
   scheduled before 0.1.0 final, with a non-ASCII regression test.
3. **Follow-up bug:** finding messages show `<url literal, N chars>` instead of the URL. A host name is not a
   secret. Redact only credentials (user-info, tokens in the query string), keep scheme and host. Fix before the
   first pre-release; add a test that the host is visible and a token is not.
4. **Not yet exercised:** a real upload to GitHub code scanning. It is done through the Action (step 6) against a
   fixtures-only project, never against this repository's real code-scanning alerts.
