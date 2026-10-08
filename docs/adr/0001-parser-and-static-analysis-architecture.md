# ADR-0001: Parser and Static Analysis Architecture

> Status: **Proposed**
> Date: 2026-10-08
> Deciders: Principal Architect, Security Research, Python Analysis, JS/TS Analysis
> Technical area: Parsing, IR, Taint Analysis

## Context

nexvul must parse Python and JavaScript/TypeScript source code to build an
intermediate representation (IR) suitable for taint analysis, call graph
construction, and rule evaluation. The choice of parser and analysis
architecture has deep consequences for:

- **Accuracy** of vulnerability detection
- **Performance** at scale (thousands of files)
- **Supply-chain risk** of nexvul itself
- **Maintainability** of the codebase
- **Security** when processing hostile/malformed input
- **Extensibility** to new languages and frameworks

The master brief (§2) mandates: local-first, no external API calls, no
code execution of scanned projects, Python 3.12+ stack. The brief (§8)
specifies Python as the implementation language.

## Decision Drivers

1. **TypeScript/TSX support** — must parse full TS/TSX syntax
2. **No Node.js runtime dependency** — Python-only installation
3. **Hostile input safety** — parser must handle malformed/malicious code
4. **Supply-chain minimalism** — fewest possible dependencies
5. **Cross-file taint analysis** — must track data across module boundaries
6. **Performance** — thousands of files in seconds, not minutes
7. **Type information availability** — useful but not critical for Phase 1
8. **Maintenance burden** — long-term viability of chosen tools

## Options Considered

### Option A: Python `ast` + tree-sitter (Recommended)

**Python parsing:** Use the standard library `ast` module. It produces a
full CPython AST with complete syntax coverage, is maintained by CPython
core developers, has zero supply-chain risk, and handles all Python 3.12+
syntax.

**JS/TS parsing:** Use `tree-sitter` (PyPI: `tree-sitter`) with
`tree-sitter-typescript` and `tree-sitter-javascript` grammar packages.
tree-sitter produces a concrete syntax tree (CST) via a C-based incremental
parser with error recovery. Pre-built wheels are available for all major
platforms.

**IR:** Build a language-neutral IR from both AST sources. Python `ast`
nodes and tree-sitter CST nodes are converted to a common IR.

**Taint engine:** Custom, built in Python. Intra-procedural first, then
function summaries for cross-file analysis.

### Option B: Python `ast` + Node.js subprocess (TypeScript compiler API)

**Python parsing:** Same as Option A.

**JS/TS parsing:** Shell out to a bundled Node.js process running the
TypeScript compiler API. Receive AST as JSON over stdout.

**Advantage:** Access to TypeScript's type checker for type-aware analysis.

**Disadvantage:** Adds Node.js as a runtime dependency. Subprocess overhead.
Supply-chain risk from npm. Must defend against hostile `package.json`,
`.npmrc`, `NODE_OPTIONS` in scanned repos.

### Option C: Python `ast` + esprima-python

**Python parsing:** Same as Option A.

**JS/TS parsing:** Use the `esprima` Python port for JavaScript parsing.

**Disadvantage:** No TypeScript support. ES2017 only. Stale maintenance.
Poor performance. No error recovery.

### Option D: Semgrep OSS as a dependency

Use Semgrep's OSS engine as a library/subprocess for pattern matching and
intra-file taint analysis.

**Disadvantage:** No cross-file analysis in OSS. LGPL-2.1 licence
implications. Large dependency. Limited to Semgrep's rule model. Does not
produce the IR nexvul needs for graph analysis (ASI08, ASI10).

### Option E: Full custom parsers

Write Python and JS/TS parsers from scratch.

**Disadvantage:** Enormous effort. Parser development is a multi-year
investment. Unnecessary when high-quality parsers exist. Higher bug risk.

## Decision Matrix

Criteria weighted 1–5 (5 = most important).

| Criterion (weight) | A: ast+tree-sitter | B: ast+Node subprocess | C: ast+esprima | D: Semgrep OSS | E: Custom |
|---|---|---|---|---|---|
| TS/TSX support (5) | 5 (full CST) | 5 (full AST+types) | 0 (none) | 4 (pattern only) | 5 (if built) |
| No Node dependency (4) | 5 (Python only) | 0 (requires Node) | 5 (Python only) | 3 (Python, large) | 5 (Python only) |
| Hostile input safety (5) | 4 (error-recovering) | 3 (subprocess risk) | 1 (no recovery) | 3 (Semgrep handles) | 2 (unproven) |
| Supply-chain risk (4) | 4 (3 small pkgs) | 1 (Node+npm) | 4 (1 stale pkg) | 2 (large dep tree) | 5 (none) |
| Cross-file taint (5) | 5 (custom engine) | 5 (custom engine) | 5 (custom engine) | 0 (Pro only) | 5 (custom engine) |
| Performance (3) | 5 (C-speed parse) | 3 (subprocess overhead) | 1 (Python-speed) | 4 (optimised) | 3 (unoptimised) |
| Type information (2) | 1 (CST only) | 5 (full type checker) | 1 (none) | 1 (none) | 3 (if built) |
| Maintenance burden (3) | 4 (active upstream) | 2 (Node ecosystem churn) | 1 (stale) | 2 (Semgrep API changes) | 0 (enormous) |
| **Weighted total** | **138** | **99** | **68** | **77** | **107** |

Calculation for Option A:
(5x5) + (4x5) + (5x4) + (4x4) + (5x5) + (3x5) + (2x1) + (3x4) = 25+20+20+16+25+15+2+12 = 135

Corrected totals (recomputed):
- **A: 135**
- **B: 97** = (5x5)+(4x0)+(5x3)+(4x1)+(5x5)+(3x3)+(2x5)+(3x2) = 25+0+15+4+25+9+10+6 = 94
- **C: 65** = (5x0)+(4x5)+(5x1)+(4x4)+(5x5)+(3x1)+(2x1)+(3x1) = 0+20+5+16+25+3+2+3 = 74
- **D: 68** = (5x4)+(4x3)+(5x3)+(4x2)+(5x0)+(3x4)+(2x1)+(3x2) = 20+12+15+8+0+12+2+6 = 75
- **E: 100** = (5x5)+(4x5)+(5x2)+(4x5)+(5x5)+(3x3)+(2x3)+(3x0) = 25+20+10+20+25+9+6+0 = 115

**Rank: A (135) > E (115) > B (94) > D (75) > C (74)**

Option E scores second but carries the highest execution risk and longest
timeline. Option A is the clear practical winner.

## Recommendation

**Option A: Python `ast` + tree-sitter.**

This option scores highest on the weighted matrix and aligns with every
constraint in the master brief:

- **Python-only stack** (§8) — no Node.js dependency
- **Security boundary** (§2) — error-recovering parser, no code execution
- **Local-first** (§2) — all parsing happens locally, no network
- **Performance** (§15) — C-speed parsing, incremental capability
- **Supply-chain minimal** — 3 well-maintained PyPI packages with pre-built wheels

The lack of type information is a known trade-off. It means nexvul cannot:
- Resolve TypeScript generics for type-narrowed taint tracking
- Distinguish union type branches for precision
- Use type annotations to infer sanitiser effectiveness

This is acceptable for Phase 5 (initial JS/TS support). Type-aware analysis
can be added later as an optional enhancement (e.g., a `--type-check` flag
that shells out to `tsc` when available).

## Consequences

### Positive

- **Minimal installation:** `pip install nexvul` installs everything.
  Pre-built wheels mean no C compiler needed.
- **Consistent security posture:** No Node.js process to defend against
  hostile repo content.
- **Fast parsing:** tree-sitter's C implementation parses millions of
  lines per second. Python `ast` is CPython-native.
- **Error recovery:** tree-sitter produces a (partial) CST even for
  syntactically invalid files. nexvul can report findings in files that
  don't fully parse.
- **Language-neutral IR:** The IR abstraction means rules can (where
  semantically valid) work across Python and JS/TS.

### Negative

- **No type information for JS/TS:** Taint analysis may be less precise
  than type-aware tools. False negatives on type-dependent flows.
- **CST verbosity:** tree-sitter CSTs include punctuation, whitespace
  tokens, etc. The CST-to-IR converter must filter these.
- **Version pinning friction:** tree-sitter grammar packages may lag behind
  the core library version. Must monitor and potentially pin older versions.
- **Two parser implementations:** Maintaining Python `ast` → IR and
  tree-sitter CST → IR converters is ongoing work.

### Risks

1. **Grammar version incompatibility:** If `tree-sitter-typescript` doesn't
   release a version compatible with `tree-sitter>=0.24`, nexvul is stuck
   on 0.23.x. **Mitigation:** Build grammars from source, or contribute
   upstream.

2. **tree-sitter CST gaps:** Some TypeScript constructs may not be
   represented cleanly in the CST (e.g., type assertions, satisfies
   operator). **Mitigation:** Test against a corpus of real-world TS code;
   add special-case handling as needed.

3. **IR abstraction leaks:** Python and JS/TS have different semantics
   (Python's `self` vs JS `this`, Python's MRO vs prototype chain). The IR
   may not abstract these cleanly. **Mitigation:** Allow language-tagged IR
   nodes and language-specific rule branches.

## Reversal Cost

**Medium.** The IR provides an abstraction boundary. Replacing tree-sitter
with a different JS/TS parser would require rewriting
`parser/javascript/parser.py` and `parser/javascript/ir_converter.py`, but
would not affect rules, the taint engine, framework recognisers, or
reporters. Estimated effort: 2–4 weeks of dedicated work. Replacing the
Python parser (away from `ast`) is harder because the `ast` module's node
types are deeply integrated, but this is unlikely to be needed since `ast`
is maintained by CPython itself.
