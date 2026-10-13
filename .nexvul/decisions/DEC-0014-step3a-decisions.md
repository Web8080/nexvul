# DEC-0014: Step 3a decisions

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Supervisor (within delegated authority) |
| Date | 2026-10-13 |
| Source | .nexvul/handoffs/phase1-step3a.md |

1. **Bare inline suppression in CI** (`# nexvul: ignore[NEX006]` with no reason, or a bare `# nexvul: ignore`):
   DEC-0004 called this a config error; the implementation and design screens treat it as a **warning, with the
   suppression not honoured and the finding staying active**. Accepted as the rule. It is the safe outcome (the
   finding is never hidden) and does not block unrelated CI. DEC-0004 §2 is amended accordingly.
2. **Backslash in filenames:** treated as an ordinary byte on POSIX; only `/` separates components. The previous
   rejection aborted the whole scan (exit 4) on one hostile filename, which is itself a denial-of-scan. Path checks
   for empty, absolute, `.`/`..` and NUL components stay. Windows remains unsupported.
3. **`--force`** (needed by screen T22) accepted. **Rich** stays out (no new dependency). **`--quiet`** deferred.
4. **Body text wrap:** 100 columns (design-system limit), not the mock-ups' ~115.
5. **Open from this step:** the repo's own `.nexvul.yml` is counted as nexvul config, not a parse gap. A YAML and
   JSON config parser is needed next (NEX007 reads MCP JSON configs); until then JSON/YAML/TOML files make a scan
   partial with reason `parser_unavailable`.
