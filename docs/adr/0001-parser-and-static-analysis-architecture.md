# ADR-0001: Parser and Static Analysis Architecture

> Status: **Proposed** (revision 2)
> Date: 2026-10-08
> Deciders: Principal Architect, Security Research, Python Analysis, JS/TS Analysis; acceptance by the
> Principal Supervisor (roadmap Phase 0 exit). Items marked *pending human approval* need the product owner.
> Technical area: parsing, isolation, IR, taint analysis, rule loading
> Detail: `docs/architecture.md` (revision 2). Threat inputs: `docs/threat-model.md` T-01..T-30, SR-01..SR-30.

## Context

nexvul must parse Python and JavaScript/TypeScript from **hostile** repositories (brief §0, §2) and build an
intermediate representation (IR) that supports cross-file taint, call graphs, workflow graphs and rule
evaluation — without ever executing, importing or building the target (brief §2, §20).

Two findings shape this decision beyond "which parser":

1. The competitive review (`docs/research/competitors/README.md`) shows **no** competitor has cross-file taint,
   and JS/TS support is heuristic or broken everywhere. These are nexvul's intended differentiators, so the
   IR and taint design must be built for them from the start, even though the thin slice (roadmap §0) ships
   intra-procedural Python first.
2. The threat model shows that the parser choice is inseparable from **how** parsing runs: `ast.parse` can
   crash the interpreter on deep nesting; native grammar code is a memory-safety surface; `signal.alarm`
   cannot bound C-level work; auto-loaded plugins and `python -m` path shadowing are code-execution vectors
   (T-01b, T-03, T-07, T-25, T-28).

Revision 1 of this ADR also contained an arithmetic error in its decision matrix (inconsistent "corrected"
totals). Revision 2 recomputes every total and shows the working.

## Decision drivers

| # | Driver | Weight (1–5) |
|---|--------|--------------|
| D1 | Full TypeScript/TSX + modern JS syntax | 5 |
| D2 | No Node.js runtime dependency (Python-only install, brief §8) | 4 |
| D3 | Hostile-input safety (error recovery, crash containment possible) | 5 |
| D4 | Supply-chain minimalism (brief §32.4) | 4 |
| D5 | Supports nexvul-owned cross-file taint and graph analysis | 5 |
| D6 | Performance at 1k–10k files (brief §15) | 3 |
| D7 | Type information | 2 |
| D8 | Long-term maintenance burden | 3 |

## Options considered (JS/TS parser; Python side is stdlib `ast` in all but F)

- **A. stdlib `ast` + tree-sitter** (`tree-sitter` + `tree-sitter-javascript` + `tree-sitter-typescript` wheels).
  CST with error recovery; C parser; prebuilt wheels; no Node.
- **B. `ast` + Node.js subprocess** running the TypeScript compiler API (or Babel/oxc/swc). Reference
  parsers and, for `tsc`, type information; but adds Node + npm supply chain, and Node must be defended
  against hostile `package.json`, `.npmrc`, `node_modules`, `NODE_OPTIONS`.
- **C. `ast` + esprima-python.** No TypeScript, ES2017 only, stale, no error recovery. Disqualified on D1.
- **D. Semgrep OSS as the engine.** Intra-file taint only in OSS; LGPL-2.1; large dependency; no IR for
  ASI08/ASI10 graph analysis.
- **E. Custom parsers for both languages.** Multi-year effort, unproven robustness.
- **F. tree-sitter for both Python and JS/TS** (adds `tree-sitter-python`). One CST pipeline and grammar
  independence from the running interpreter, but loses CPython-exact semantics (encoding, NFKC identifiers,
  exact syntax acceptance) that the threat model relies on (T-18, SR-20).

oxc/swc Python bindings do not exist (`docs/research/tooling/js-ts-parsers.md`, verified 2026-10-08).

## Decision matrix (score 0–5 × weight)

| Criterion (weight) | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| D1 TS/TSX (5) | 5 | 5 | 0 | 4 | 5 | 5 |
| D2 No Node (4) | 5 | 0 | 5 | 3 | 5 | 5 |
| D3 Hostile input (5) | 4 | 3 | 1 | 3 | 2 | 4 |
| D4 Supply chain (4) | 4 | 1 | 4 | 2 | 5 | 4 |
| D5 Own cross-file/graph analysis (5) | 5 | 5 | 5 | 0 | 5 | 5 |
| D6 Performance (3) | 5 | 3 | 1 | 4 | 3 | 5 |
| D7 Types (2) | 1 | 5 | 1 | 1 | 3 | 1 |
| D8 Maintenance (3) | 4 | 2 | 1 | 2 | 0 | 3 |

Working (score × weight, in criterion order):

- **A** = 25 + 20 + 20 + 16 + 25 + 15 + 2 + 12 = **135**
- **B** = 25 + 0 + 15 + 4 + 25 + 9 + 10 + 6 = **94**
- **C** = 0 + 20 + 5 + 16 + 25 + 3 + 2 + 3 = **74**
- **D** = 20 + 12 + 15 + 8 + 0 + 12 + 2 + 6 = **75**
- **E** = 25 + 20 + 10 + 20 + 25 + 9 + 6 + 0 = **115**
- **F** = 25 + 20 + 20 + 16 + 25 + 15 + 2 + 9 = **132**

Rank: **A (135) > F (132) > E (115) > B (94) > D (75) > C (74).**

Caveats: the scores are judgements, not measurements. E's score is inflated by D4/D2 because it has no
dependencies, but it carries the largest delivery risk, which the matrix does not weight — it is rejected on
feasibility. A and F are close; A wins on Python-semantic fidelity (not captured in the matrix), and F is kept
as a **fallback** for Python files the running interpreter cannot parse (see Consequences, R-4).

## Decision

Adopt **Option A** together with the following binding architecture choices (each detailed in
`docs/architecture.md`):

1. **Parsers.** Python via stdlib `ast` (decoded per PEP 263, SR-20); JS/TS/JSX/TSX via tree-sitter grammar
   wheels, pinned by hash (Phase 5). Manifests (JSON/YAML/TOML, lockfiles, MCP configs) via safe loaders only.
2. **Process isolation for all parsing and analysis** (architecture §5). A supervisor assigns one file at a
   time to `spawn`-started worker processes with POSIX resource limits; per-file and per-analysis wall-clock
   limits are enforced by **hard kill** of the worker, never `signal.alarm`. Worker death or timeout is
   recorded per file. Worker→supervisor IPC is size-capped JSON, never pickle (SR-01, SR-03, SR-09).
3. **Language-neutral IR** with frozen nodes and analysis facts; per-file IR is a pure function of file bytes,
   path and tool versions (architecture §6).
4. **nexvul-owned taint engine**: intra-procedural first (thin slice), then function summaries computed
   bottom-up over call-graph SCCs with deterministic budgets, then cross-file via import resolution, then
   store-linked second-order flows for ASI06 (architecture §8). Precision-biased: unresolved calls do not
   propagate taint, and this is counted and reported.
5. **Version-aware recognition**: framework facts include the resolved version from lockfiles (read as data),
   and rule defaults come from a cited, versioned table (architecture §7.2). MCP recognisers support both the
   2025-11-25 and 2026-07-28 spec eras (architecture §7.3).
6. **Built-in rules only** from a frozen registry until after 1.0; no entry-point discovery (SR-22)
   *[plugin deferral pending human approval]*.
7. **Isolated startup**: console-script entry point; `python -m nexvul` re-executes with `-P -E`; startup
   aborts if any loaded module resolves inside the scan root (SR-02).
8. **No Semgrep, no Node.js, no network** at runtime.

## Consequences

### Positive

- `pip install nexvul` needs no compiler and no Node.js; nothing in the scan path executes target code.
- Parser crashes, hangs and memory blow-ups become per-file `partial` entries instead of a dead or hung scan,
  and are visible in the completeness block (SR-18).
- Cross-file taint and real JS/TS parsing — the two gaps no competitor fills — share one IR and one engine.
- Rules are independent of the parser; replacing tree-sitter would touch only `parser/javascript|typescript`.

### Negative

- **No type information for JS/TS.** Type-dependent flows are false negatives. A future, opt-in type-aware
  mode would need its own ADR and threat-model revision (it would reintroduce Node or `tsc`).
- **CST verbosity**: the tree-sitter → IR converter must filter punctuation/trivia nodes.
- **Two front ends** (Python `ast`, tree-sitter) to maintain and keep semantically aligned.
- **Process-isolation cost**: spawn and JSON IPC overhead per file; measured in the Phase 1 baseline, not
  assumed.
- **Interpreter-bound Python grammar**: `ast.parse` rejects syntax newer than the interpreter nexvul runs on;
  such files are reported as `syntax_unsupported_by_runtime` (partial).

### Risks

| ID | Risk | Mitigation |
|----|------|------------|
| R-1 | tree-sitter grammar wheels are native code parsing attacker input (T-28) | hash-pinned wheels; worker isolation contains crashes; fuzzing in Phase 8; OS sandboxing post-1.0 |
| R-2 | Grammar/core version skew: research notes `tree-sitter-typescript` 0.23.x declaring `tree-sitter~=0.23` while core is 0.26 (compatibility partly UNVERIFIED) | pin a known-compatible set; build grammars from source if needed; re-verify at Phase 5 start |
| R-3 | CST gaps for some TS constructs (`satisfies`, assertions, decorators) | corpus-based tests; language-tagged IR escape hatch |
| R-4 | Running interpreter cannot parse newer Python syntax | report as partial; evaluate Option F (tree-sitter-python) as a fallback parser in Phase 3 |
| R-5 | IR abstraction leaks between Python and JS semantics | language-tagged attributes; language-specific rule branches allowed |
| R-6 | Memory limits weak on macOS/Windows | pre-parse size and nesting caps are the primary bound; documented |
| R-7 | Precision bias hides real flows | unresolved-call counts reported; recall measured by the benchmark |

## Reversal cost

**Medium.** Swapping the JS/TS parser rewrites `parser/javascript|typescript` (estimate 2–4 weeks) without
touching rules, taint, recognisers or reporters. Moving Python off `ast` (e.g. to Option F) is larger because
decoding and location semantics are tied to CPython, but the IR boundary contains it. Reversing process
isolation is not contemplated: it is required by SR-03.

## Pending human decisions referenced

Plugin deferral to post-1.0 (D8), tighten-only repo config in CI (D1), suppression justification and
PR-added-suppression listing (D2/D3), partial-scan-fails-CI default (D4), ASI multi-labelling (Q1/Q2), and new
dependencies such as a git-index reader or `platformdirs` (D7). See `docs/architecture.md` §19.
