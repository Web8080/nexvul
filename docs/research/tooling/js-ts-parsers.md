# JS/TS Parser Options — Research Notes for nexvul

> Last updated: 2026-10-08. Sources: PyPI, GitHub repos, npm registry.
> Items marked [UNVERIFIED] need direct confirmation before committing.

## CRITICAL: This decision gates Phase 5 (JS/TS support)

nexvul must parse TypeScript, TSX, JavaScript, and JSX to build an IR
(call sites, symbol refs, imports/exports, agent/tool declarations). The
parser must run from Python with no Node.js runtime requirement (brief §2:
local-first, §8: Python 3.12+ stack).

---

## Option 1: tree-sitter (py-tree-sitter + language grammars)

### What It Is

tree-sitter is an incremental parsing framework written in C. It generates
concrete syntax trees (CSTs) from formal grammars. Python bindings
(`tree-sitter` on PyPI) wrap the C library.

### PyPI Packages

| Package | Version | Status |
|---|---|---|
| `tree-sitter` | 0.26.0 (June 2026) | Active, pre-built wheels |
| `tree-sitter-typescript` | 0.23.2 (Nov 2024) | Provides TS + TSX grammars |
| `tree-sitter-javascript` | 0.23.1 [UNVERIFIED] | Separate grammar package |

**Wheel availability:** `tree-sitter` ships pre-built wheels for:
- macOS x86_64 + arm64
- manylinux (x86_64, aarch64)
- musllinux
- Windows

The grammar packages use the stable ABI tag (`cp39-abi3`), so one wheel
covers Python 3.9+.

### Version Compatibility Warning

`tree-sitter-typescript` 0.23.x declares `tree-sitter~=0.23` as a
dependency. The core `tree-sitter` package is at 0.26.0. **These may not
be compatible.** Options:
1. Pin `tree-sitter==0.23.x` (miss improvements in 0.24–0.26)
2. Wait for grammar packages to catch up
3. Build grammars from source against 0.26 [UNVERIFIED feasibility]
4. Use `tree-sitter-languages` bundle (but it's unmaintained for new versions)

### Evaluation

| Criterion | Rating | Notes |
|---|---|---|
| TS/TSX coverage | Excellent | Full grammar, CST-level, handles all syntax |
| Accuracy | Excellent | Error-recovering parser; handles malformed input |
| Type info | None | CST only — no type resolution, no type inference |
| Footprint | Small | ~2 MB compiled; C library, no runtime deps |
| Supply-chain risk | **Low** | tree-sitter org on GitHub; widely used (GitHub, Neovim, Helix); C code compiled at wheel build time, no JS runtime |
| Crash/DoS on hostile input | **Good** | Error-recovering by design; tested against fuzzing. Still need per-file size/depth limits |
| Sandboxing | Good | Pure C parser, no eval/exec, no network, no filesystem |
| Performance | **Excellent** | Incremental; benchmarks at millions of lines/sec; written in C |

### Pros
- No Node.js dependency
- Error-recovering (handles malformed/hostile code gracefully)
- Incremental parsing (fast re-parse on changes)
- Battle-tested (GitHub code navigation, syntax highlighting)
- Pre-built wheels (no C compiler needed at install time)
- Deterministic, no side effects

### Cons
- CST, not AST — more verbose tree, need to skip whitespace/punctuation nodes
- No type information — cannot resolve `typeof x`, generics, type narrowing
- Version pinning friction between core and grammar packages
- Grammar packages are separate repos with their own release cadence

---

## Option 2: esprima (Python port)

### What It Is

Pure Python port of the Esprima JavaScript parser. Produces ESTree-format ASTs.

### PyPI Package

| Package | Version | Status |
|---|---|---|
| `esprima` | 4.0.1 [UNVERIFIED] | Last release ~2019; limited maintenance |

### Evaluation

| Criterion | Rating | Notes |
|---|---|---|
| TS/TSX coverage | **None** | JavaScript only (ES2017). No TypeScript support. |
| Accuracy | Good (for JS) | Faithful port of esprima.js; ES2017 compliant |
| Type info | None | |
| Footprint | Small | Pure Python, no native deps |
| Supply-chain risk | **Low** | Pure Python, auditable |
| Crash/DoS on hostile input | **Poor** | Pure Python parser; no fuzz testing evidence; stack overflow risk on deep nesting; no timeout/depth limits built in |
| Sandboxing | Good | Pure Python, no exec/eval |
| Performance | **Poor** | Python-speed parsing. The `pyesprima` variant is documented as ~100x slower than Node esprima |

### Pros
- Zero native dependencies
- Auditable pure Python
- ESTree output (well-documented AST format)

### Cons
- **No TypeScript support** — disqualifying for nexvul
- Stale maintenance (no updates since ~2019)
- ES2017 only — missing ES2020+ syntax (optional chaining, nullish coalescing, etc.)
- Poor performance on large files
- No error recovery (parse fails on first syntax error)

**Verdict: DISQUALIFIED.** No TypeScript support.

---

## Option 3: Shell out to bundled Node + TypeScript compiler / Babel / oxc / swc

### Approach

Ship a Node.js subprocess that runs a JS/TS parser and returns JSON AST
over stdout/pipe.

### Sub-options

| Parser | AST Format | TS Support | Speed |
|---|---|---|---|
| TypeScript compiler API | TS AST | Full (with types) | Moderate |
| Babel (`@babel/parser`) | ESTree/Babel AST | Full | Moderate |
| oxc (`oxc-parser` npm) | ESTree-compatible | Full | Very fast (Rust) |
| swc (`@swc/core` npm) | SWC AST | Full | Very fast (Rust) |

### Evaluation

| Criterion | Rating | Notes |
|---|---|---|
| TS/TSX coverage | **Excellent** | All options handle full TS/TSX |
| Accuracy | Excellent | Reference parsers, especially tsc |
| Type info | **tsc only** | Only TypeScript compiler API provides type checking |
| Footprint | **Large** | Node.js runtime (~50-80 MB) + npm packages |
| Supply-chain risk | **HIGH** | Node.js + npm ecosystem = large dependency tree. `@babel/parser` has 0 deps but Babel ecosystem is large. `@swc/core` ships native binaries per platform. `oxc-parser` is newer with smaller community. |
| Crash/DoS on hostile input | **Variable** | Parsers are production-grade but Node subprocess adds attack surface. Must handle: subprocess hangs, OOM, malicious `package.json`/`.npmrc` in scanned repo, prototype pollution |
| Sandboxing | **Poor** | Node.js has full system access. Must NOT run from within scanned repo (could load malicious `node_modules`). Must use `--no-warnings --no-deprecation` and stripped env. |
| Performance | Good–Excellent | Parser itself fast, but subprocess spawn + JSON serialisation adds overhead per file. Amortise with batch mode. |

### Pros
- Access to reference-quality parsers
- TypeScript compiler can provide type information
- Battle-tested against real-world code

### Cons
- **Adds Node.js as a runtime dependency** — contradicts Python-only stack (§8)
- **Supply-chain risk** — npm install in CI pulls hundreds of packages
- Subprocess overhead per file (or batch protocol complexity)
- Must defend against hostile repos influencing Node (`.npmrc`, `package.json`,
  `node_modules/.hooks`, `NODE_OPTIONS` env var)
- Bundling Node binary bloats package size

**Verdict: POSSIBLE BUT COSTLY.** Only justified if type information is
essential. For nexvul Phase 5 (CST-level analysis), tree-sitter is preferred.
Type-aware analysis could be a later phase.

---

## Option 4: oxc / swc Python Bindings

### Status [VERIFIED 2026-10-08]

- **oxc Python bindings:** No official package on PyPI. An unofficial
  `oxfmt` package distributes the oxc formatter binary as a wheel, but
  it is NOT a parser binding. The maintainer (dhruvkb/oxc-py) notes it is
  "not an official distribution." No AST access from Python.

- **swc Python bindings:** No package on PyPI. SWC's GitHub repo shows 0.0%
  Python in its language breakdown. The `swc-registry` package on PyPI is
  unrelated.

### Evaluation

| Criterion | Rating | Notes |
|---|---|---|
| TS/TSX coverage | N/A | No Python bindings exist |
| Supply-chain risk | N/A | Cannot evaluate what doesn't exist |

**Verdict: NOT AVAILABLE.** Neither oxc nor swc offers usable Python
bindings for AST access as of October 2026.

---

## Option 5: Other Pure-Python Parsers

| Parser | JS Support | TS Support | Maintenance | Notes |
|---|---|---|---|---|
| `pyjsparser` | ES5+ (partial) | No | Stale | Based on esprima.js |
| `calmjs.parse` | ES5 only | No | Low | Fails on modern syntax |
| `Js2Py` | ES5.1 | No | **Archived** | Interpreter, not just parser |
| `slimit` | ES5 | No | Stale | |

**Verdict: ALL DISQUALIFIED.** None supports TypeScript or modern JavaScript.

---

## Comparison Matrix

| Criterion | tree-sitter | esprima-py | Node subprocess | oxc/swc bindings |
|---|---|---|---|---|
| TS/TSX | Yes | **No** | Yes | **N/A** |
| Modern JS (ES2020+) | Yes | **No** | Yes | **N/A** |
| Type info | No | No | tsc only | **N/A** |
| Python-only (no Node) | **Yes** | Yes | **No** | **N/A** |
| Pre-built wheels | Yes | Yes (pure) | N/A | **N/A** |
| Performance | Excellent | Poor | Good | **N/A** |
| Supply-chain risk | Low | Low | **High** | **N/A** |
| Hostile input safety | Good | Poor | Variable | **N/A** |
| Error recovery | Yes | No | Variable | **N/A** |
| Maintenance | Active | Stale | Active (per parser) | **N/A** |

---

## Recommendation

**tree-sitter** is the clear winner for nexvul's JS/TS parsing needs:

1. Only viable option that supports TypeScript WITHOUT a Node.js dependency
2. Lowest supply-chain risk (C library, pre-built wheels, no npm)
3. Best hostile-input handling (error-recovering, fuzz-tested)
4. Best performance (C-speed parsing, incremental)
5. Aligns with brief §2 (local-first, no external runtime requirements)

**Mitigation for cons:**
- CST verbosity → Build a thin AST extraction layer on top of tree-sitter CST
- No type info → Accept this limitation; type-aware analysis is a future phase
- Version pinning → Pin `tree-sitter==0.23.x` with grammar packages initially;
  track upstream for ABI stabilisation

**Risk:** If `tree-sitter-typescript` and `tree-sitter-javascript` grammar
packages do not release versions compatible with `tree-sitter>=0.24`, nexvul
is pinned to 0.23.x. Mitigation: build grammars from source, or contribute
upstream updates.
