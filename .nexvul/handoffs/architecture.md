# Handoff — Architecture (Phase 0, revision 2)

- **From:** Principal Architect
- **To:** Principal Supervisor; cc Security Gatekeeper / Threat Modeller, QA/Test, DevSecOps, Python Analysis,
  JS/TS Analysis, Framework Intelligence, Documentation
- **Date:** 2026-10-08
- **Status:** Proposed. Nothing implemented; no code; no commits.

## 1. Files changed

| File | Change |
|------|--------|
| `docs/architecture.md` | Rewritten as revision 2 (Proposed). |
| `docs/adr/0001-parser-and-static-analysis-architecture.md` | Revision 2, still Proposed. Matrix arithmetic fixed; Option F (tree-sitter-python) added; the decision now also covers isolation, IR, taint, version facts, rule loading and startup. |

## 2. What changed (review defects → fix)

| # | Defect in rev 1 | Fix (architecture §) | SR / T |
|---|-----------------|----------------------|--------|
| 1 | Cache in `.nexvul/cache/` inside the scanned repo, clashing with the agent workspace | Per-user cache dir only; key = repo identity + content hash + tool/config/rule versions; HMAC with a per-user key; schema-validated; content hash re-checked; cache inside the scan root is refused; `--no-cache` in the Action (§14) | SR-07, SR-08, T-21 |
| 2 | `signal.alarm` timeouts; bare `multiprocessing.Pool` | Supervisor-owned `spawn` workers, one file in flight, hard kill on timeout, rlimits, per-analysis deterministic budgets plus a wall-clock backstop, JSON-only IPC (§5) | SR-03, SR-05, SR-09, T-03, T-07 |
| 3 | Entry-point plugin auto-loading | Frozen built-in registry with integrity hash; no `entry_points()` before 1.0; later model = declarative packs first, code plugins only by explicit allowlist (§11.3–11.4) | SR-22, T-25 |
| 4 | Discovery "respecting .gitignore" | Tracked files scanned regardless of ignore files; ignore rules and built-in excludes apply only to untracked files; bounded `.git/index` reader, no `git` execution; every exclusion counted (§4) | SR-16, T-16 |
| 5 | Over-limit files "skipped with a warning" | Completeness ledger; partial status; exit code 3 (precedence 2 > 4 > 3 > 1 > 0); trusted-string terminal footer; SARIF `executionSuccessful=false`; HTML banner (§12.3–12.4) | SR-18, SR-19, T-20, T-22 |
| 6 | Fixture `test_positive_001.py` would be executed by pytest | `case_<nnn>_<slug>.py.fixture` (non-importable), fed to an in-process virtual-tree API; `python_files`/`norecursedirs`/`collect_ignore_glob`; meta-test bans real source extensions under `tests/rules/` and `benchmarks/` (§11.6) | brief §2, §20 |
| 7 | `python -m nexvul` can import attacker modules | Console script is the documented entry point; `__main__` re-execs with `-P -E`; startup aborts if any loaded module lies in the scan root, checked in workers too (§2.1–2.2) | SR-02, T-01b |
| 8 | pre-commit filenames parsed as options | `nexvul precommit` requires a literal `--` (fails closed without it), accepts no output-writing options, validates every path (§2.3) | SR-14, T-14 |

Also integrated: versioned defaults table + lockfile version facts, e.g. LangGraph `recursion_limit` 25 /
10000 / 10007 by version (§7.2); MCP 2025-11-25 vs 2026-07-28 era recognisers (§7.3); self-contained,
CSP-locked, escaped HTML report (§13); IR facts (`store_identity`, `McpEra`, `AnalysisLimited`) and taint
phases T1–T5 aimed at cross-file ASI06 and real JS/TS (§6, §8); an SR traceability table (§16); a pending
decisions section (§19) and an open-risks register (§20).

## 3. Pending human decisions (recommended defaults, listed in architecture §19)

P1 tighten-only repo config in CI · P2 suppression justification in CI and PR-added suppressions listed ·
P3 partial scans fail CI · P4 plugins deferred to post-1.0 · P5 ASI multi-labelling for ASI09/ASI10 rules.
Still open from the threat-model handoff: D7 (git-index reader, `platformdirs`, HTML builder dependencies).

## 4. Requests to other owners

- **Threat Modeller:** amend SR-06 to allow the bounded, read-only `.git/index` / `.git/HEAD` carve-out
  (architecture §4.2), or reject it and choose another way to list tracked files. Threat-model §1/§9 still
  describe the rev-1 architecture (in-repo cache, entry points); refresh them. Its header says the brief has
  no §20, but the current brief does have §20.
- **QA/Test:** update test-strategy §4.1 from `case_<nnn>_<slug>.py` to `.py.fixture` + virtual-tree harness;
  add the meta-test; add exit-code precedence and `precommit` missing-`--` tests.
- **DevSecOps:** Action passes `--no-cache`, `--changed-lines`, `--config-base`, and invokes with `-I` from an
  isolated venv.
- **Framework Intelligence:** turn `docs/research/frameworks/README.md` §2 into the cited defaults table
  (`nexvul/data/defaults_table/`), and confirm the MCP names marked UNVERIFIED before recognisers use them.

## 5. Remaining open risks

1. Native parsers are a memory-safety surface; process isolation contains crashes, not exploits. OS sandboxing
   is post-1.0 (R-1, R-2).
2. Memory caps are best-effort on macOS and Windows (R-3).
3. `ast.parse` rejects syntax newer than the running interpreter, which gives partial scans; a
   tree-sitter-python fallback is not decided (R-4).
4. Precision bias causes false negatives through unresolved calls. These are counted, not hidden (R-5).
5. The `.git/index` reader is new security-critical parsing code (R-6).
6. Lockfiles are attacker-controlled and can change severity wording, though they cannot suppress a finding (R-7).
7. The cost of spawning workers and of JSON IPC at 10k files has not been measured (R-8).
8. ASI10 capability weights are uncalibrated placeholders (R-9).
9. The grammar/core version skew in tree-sitter is partly UNVERIFIED and must be re-checked at the start of Phase 5.
