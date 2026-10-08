# nexvul — Architecture

> Status: **Proposed** (Phase 0, revision 2). No implementation exists. Every behaviour below is a design
> requirement, not a description of shipped code (brief §33).
> Owner: Principal Architect. Last updated: 2026-10-08.
> Binding inputs: `docs/brief/master-brief.md` §2, §7–10, §15, §19, §20; `docs/threat-model.md` (T-01..T-30,
> SR-01..SR-30); `docs/security-model.md`; `docs/roadmap.md` (thin slice first); `docs/test-strategy.md`.
> Companion ADR: `docs/adr/0001-parser-and-static-analysis-architecture.md`.
>
> Revision 2 fixes eight defects found by independent review of revision 1 (in-repo cache, `signal.alarm`
> timeouts, auto-loaded plugins, `.gitignore`-driven discovery, skip-as-warning, executable fixture names,
> `python -m` shadowing, pre-commit argument injection). Where a design choice answers a threat-model
> requirement, the SR/T ID is cited inline. Items marked **[pending human approval]** are recommended defaults,
> collected in §19.

**A clean nexvul result never proves an agent system is secure.** The architecture is built so that nexvul
can say exactly what it did and did not analyse (§12.3), and so that it never claims more than that.

---

## 1. Overview

### 1.1 Pipeline and process boundaries

```
 nexvul (console script, isolated startup §2)
   |
   v
 +------------------------------ SUPERVISOR process (trusted code) -------------------------------+
 |  CLI args / env (trusted)   user config (trusted)   repo .nexvul.yml (UNTRUSTED, TB-2, §3)     |
 |        \_________________________|_______________________/                                     |
 |                          [Effective config + provenance]  (SR-15, SR-27, SR-28)               |
 |                                    |                                                          |
 |                          [Discovery: git index / walk]  (§4; SR-06, SR-16)                     |
 |                                    |   file manifest (path, size, kind, inclusion reason)     |
 |                          [Scheduler + completeness ledger]  (§5, §12.3; SR-03, SR-18)          |
 |                                    |                                                          |
 |      +--------- JSON over pipes, size-capped, schema-checked (no pickle) ---------+          |
 |      v                                v                                            v          |
 |  [Parse worker 1]  ...  [Parse worker N]   per-file: read bounded bytes -> parse -> IR       |
 |   (rlimits, hard kill on timeout; one file in flight per worker; §5)                         |
 |      |                                                                                       |
 |      v   per-file IR + local summaries  <---->  [Cache: per-user dir, HMAC, §14] (SR-08)       |
 |  [Repo model: module map, symbol tables, lockfile/version facts §7]                           |
 |      |                                                                                       |
 |      v                                                                                       |
 |  [Analysis worker]: call graph -> cross-file summaries -> taint -> framework facts ->         |
 |                     graph/capability models -> rule evaluation   (budgets + hard kill, §8)   |
 |      |                                                                                       |
 |      v                                                                                       |
 |  [Normaliser]: dedupe, fingerprint, suppressions, ranking, completeness, exit code (§12)      |
 |      |                                                                                       |
 |      v                                                                                       |
 |  [Reporters]: terminal | JSON | SARIF | HTML — one shared untrusted-string sanitiser (§13)    |
 +-----------------------------------------------------------------------------------------------+
```

The supervisor never parses untrusted bytes itself beyond what discovery needs (directory entries, `lstat`,
the git index in a bounded parser — §4.2). All source and manifest parsing happens in disposable workers
(SR-03). The supervisor is the only process that writes outputs or the cache (SR-07).

### 1.2 Stages

| # | Stage | Runs in | Key requirement |
|---|-------|---------|-----------------|
| 1 | Startup hygiene | supervisor | no module import from the scan root (§2, SR-02) |
| 2 | Effective config | supervisor | trust ranking, tighten-only from repo config in CI (§3, SR-15) |
| 3 | Discovery | supervisor | tracked files regardless of ignore files; every exclusion counted (§4, SR-16) |
| 4 | Language & manifest detection | supervisor (extension/name) + worker (content sniff) | binary sniff, encoding per PEP 263 (SR-20) |
| 5 | Parsing → per-file IR | parse workers | limits + hard kill (§5, SR-03/04/05) |
| 6 | Repo model | supervisor | module map, imports, lockfile version facts (§7) |
| 7 | Analysis | analysis worker | call graph, summaries, taint, graphs, rules; deterministic budgets (§8–11) |
| 8 | Normalisation | supervisor | completeness, suppressions, exit code (§12) |
| 9 | Reporting | supervisor | sanitised output in all formats (§13, SR-10..SR-13) |

### 1.3 Thin-slice mapping (roadmap §0)

The architecture is the 1.0 target; it is **built incrementally**, and the IR grows only when a shipping rule
needs it (roadmap Phase 1 risk).

| Component | Phase 1 (foundation) | Phase 2 (slice) | Later |
|-----------|----------------------|-----------------|-------|
| Startup hygiene, CLI, exit codes, completeness | full | — | — |
| Discovery (git index + walk), limits, worker isolation | full | — | OS sandbox (seccomp/landlock/sandbox-exec) post-1.0 |
| Python parse → IR | modules, functions, calls, assignments, returns, imports | as slice rules need | — |
| Taint | — | intra-procedural | summaries (P3), cross-file (P3) |
| Framework recognisers, lockfile facts | — | only what S1–S3 need | full (P4); JS/TS (P5) |
| Reporters | terminal, JSON | SARIF, HTML | — |
| Cache | **none** | none | P3 (per-user, HMAC) |
| Rule registry | built-in, frozen | built-in | declarative packs post-1.0 (§11.4) |

---

## 2. Invocation and startup hygiene (T-01b, T-14; SR-02, SR-14)

### 2.1 Supported invocations

| Invocation | Status | Why |
|------------|--------|-----|
| `nexvul …` (console-script entry point) | **documented default** | `sys.path[0]` is the script's directory (venv `bin/`), not the CWD |
| `python -I -m nexvul …` / `python -P -m nexvul …` | supported; used by the Action | `-I` (isolated) / `-P` (`PYTHONSAFEPATH`, Python ≥ 3.11) stop the CWD being prepended to `sys.path` |
| `python -m nexvul …` (no flag) | tolerated via re-exec | see §2.2 |

The GitHub Action installs nexvul from hash-pinned artefacts into its own virtual environment and invokes it
with `-I`; it never installs into the scanned project's environment (SR-21, T-25).

### 2.2 Startup guard

1. `nexvul/__main__.py` imports only `sys` and `os` (already loaded by the interpreter) before checking
   `sys.flags.safe_path or sys.flags.isolated`. If neither is set, it re-executes itself with
   `os.execv(sys.executable, [sys.executable, "-P", "-E", "-m", "nexvul", *argv])` so that nexvul's own
   dependencies (`yaml`, `click`, `rich`, …) are imported from a clean path. (`-I` is not forced on re-exec
   because it also disables user site-packages, which would break `pip install --user` installs.)
2. After CLI parsing, and before any file in the target is opened, the supervisor resolves each scan root and
   asserts that **no loaded module's `__file__`** (from `sys.modules`) resolves inside a scan root. On violation
   it aborts with exit code 4 and names the shadowing module (fail closed, SR-02). The same assertion runs at
   the start of every worker.
3. nexvul never appends a scan root to `sys.path`, never `chdir`s into it for import purposes, and reads only
   `NEXVUL_*`, `CI`, `GITHUB_ACTIONS`, `NO_COLOR` and the platform cache-dir variables from the environment
   (T-19).
4. `nexvul doctor` reports interpreter flags, the resolved path of every nexvul dependency, and warns when a
   dependency resolves inside the current directory or a user-writable location outside the venv.

Residual: `PYTHONPATH`/`.pth` manipulation of the environment nexvul is installed in is out of scope (the
attacker would already control the environment); the module-origin assertion still catches the case where the
path points into the scan root.

### 2.3 pre-commit integration (T-14; SR-14)

pre-commit runs `entry + args + filenames`. A staged file named `--output=/home/dev/.bashrc` must never be
parsed as an option.

- The hook uses a dedicated subcommand: `entry: nexvul precommit`, default `args: ["--"]`.
- `nexvul precommit` **requires** a literal `--` in argv; every token after it is a path. If `--` is missing
  (e.g. a user overrode `args` without it) the command fails closed with exit code 2 and an explanation.
  Users who add options write `args: ["--fail-on=high", "--"]`.
- `precommit` accepts no output-writing options (`--output`, `--format html|sarif`); it prints to the terminal
  only. This removes the arbitrary-write primitive even if separation were bypassed.
- Every positional path is validated: no NUL or control characters; relative after normalisation; resolves
  (without following symlinks) inside the repository root; is a regular file (`lstat`). Invalid paths are
  rejected with exit 2, never silently dropped.
- Scope is recorded: completeness `scope = "explicit-paths"` with the path count, and the summary states that
  cross-file context was limited to the given files (§12.3).

The general `scan` command also validates that every positional root exists and that `--output` refuses to
overwrite a file not previously written by nexvul unless `--force` is given (SR-14, SR-07).

---

## 3. Configuration and trust (T-04, T-15; SR-15, SR-27, SR-28)

### 3.1 Sources and precedence

| Rank (high → low) | Source | Trust |
|---|---|---|
| 1 | CLI flags / GitHub Action inputs | trusted |
| 2 | User config (`~/.config/nexvul/config.yml` or platform equivalent) | trusted |
| 3 | Base-branch config passed explicitly (`--config-base PATH`, supplied by the Action) | trusted ref |
| 4 | Repo-local `.nexvul.yml` in the scanned tree | **untrusted** |
| 5 | Built-in defaults | trusted |

Every effective key records its source, and the output carries the config file paths, refs and SHA-256 hashes
(SR-27).

### 3.2 Loading rules

- Size cap 64 KiB before parsing; `yaml.safe_load` (C `CSafeLoader` when available) only; a compose-level
  pass rejects anchors/aliases; depth cap; strict schema with unknown-key rejection (SR-28, T-04).
- All paths in config are repo-relative, normalised, with absolute paths and `..` rejected (SR-28, T-08).
- Repo-local config can **never** set: output paths, cache location, plugin/rule-pack sources, regexes, or
  anything that causes a read outside the scan root (T-09, SR-07, SR-09, SR-22).

### 3.3 Tighten-only in CI [pending human approval — D1]

CI mode is enabled by `--ci` or automatically when `CI=true` / `GITHUB_ACTIONS=true`.

- Each key has a declared direction: enabling rules, lowering `fail_on`, raising `max_files`, enabling
  `cross_file` = **tighten**; disabling rules, adding `exclude`, raising `fail_on`, lowering limits, disabling
  inline-suppression checks = **loosen**.
- In CI mode, tightening values from the PR-head `.nexvul.yml` are applied; loosening values are applied only
  from ranks 1–3. Loosening values found in PR-head config and not applied are listed under
  `protections_weakened_by_repo_config` with status `ignored`; loosening values that *were* applied from a
  trusted ref are listed with status `applied` (SR-15).
- Outside CI mode the repo config is honoured in full (local developer use), and every loosening is still
  listed in the output.

---

## 4. Discovery policy (T-05, T-08, T-16, T-22; SR-06, SR-16)

### 4.1 What is in scope

| Target type | Default file set | Ignore files |
|-------------|------------------|--------------|
| git work tree | **all tracked files** (from the index) ∪ untracked files not matched by ignore rules | `.gitignore` applies **only to untracked files**; tracked files are scanned regardless (SR-16) |
| plain directory | every regular file under the root | not honoured by default; `--respect-ignore-files` (trusted sources only) |
| `nexvul precommit` | the validated paths given after `--` | n/a |

Rationale: a file committed with `git add -f` and then listed in `.gitignore` ships to production; skipping it
would let ADV-2 hide code (T-16).

Built-in default exclusions (`node_modules/`, `.venv/`, `venv/`, `site-packages/`, `dist/`, `build/`, `.tox/`)
apply **only to untracked files**. A tracked `node_modules/evil.js` is scanned. Exclusions from trusted config
are honoured and counted; exclusions from repo config follow §3.3.

The scanned repo's own `.nexvul/` directory is treated as ordinary repository content (scanned like any other
files). It is never read as configuration, cache, baseline or rule source, and its presence is reported
(T-21).

### 4.2 Reading the git index

- The tracked-file list comes from an in-house, read-only parser of `.git/index` (versions 2–4), run with a
  size cap and an entry-count cap. nexvul **does not execute `git`** against the target (a hostile
  `.git/config` can configure hooks/fsmonitor that execute on `git` commands; and SR-01 forbids running target
  tooling). Dependency choice (in-house reader vs. a pure-Python library) is decision D7 in the threat-model
  handoff [pending human approval].
- This is a deliberate, narrow carve-out from SR-06's "never read `.git/`": only `.git/index` and `.git/HEAD`
  are read, as bounded data, never `.git/config`, hooks or objects. The threat model needs a matching amendment
  (handoff item).
- `.git` as a file (worktrees/submodules: `gitdir:` pointer) is followed only if the target stays inside the
  scan root; otherwise the tree is scanned as a plain directory and this is reported.
- Index entries that are missing on disk, sparse/skip-worktree, or gitlinks (submodules) are counted in
  completeness (`tracked_missing_on_disk`, `submodule_not_scanned`). Submodules are not traversed in v1.
- Index parse failure ⇒ fall back to plain-directory mode and record `git_index_unreadable` (partial).

### 4.3 File-system safety (SR-06)

- `os.scandir` with `follow_symlinks=False`; only `S_ISREG` files are candidates. FIFOs, devices, sockets are
  counted as `special_file` and never opened.
- Symlinks are not followed by default; when `--follow-symlinks` (trusted sources only) is set, targets must
  resolve inside the scan root; `/proc`, `/dev`, `/sys` are refused absolutely (T-08).
- Files are opened with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, then `fstat` re-checks `S_ISREG`, device/inode
  against the `lstat`, and size (TOCTOU). At most `max_file_size + 1` bytes are read.
- `.git/` is never descended into by the walker (§4.2 is the only exception).
- Global caps: `max_files`, max directory depth, total bytes, global wall-clock. Hitting any cap stops further
  discovery/analysis and makes the scan **partial** (T-22).
- Deterministic order: manifest sorted by normalised path bytes.

Every file that is discovered but not analysed — for any reason — is recorded in the completeness ledger
(§12.3) with a reason code. Nothing is dropped at debug log level only (T-22).

---

## 5. Parsing and isolation (T-02, T-03, T-07; SR-03, SR-04, SR-05, SR-09)

### 5.1 Why processes, not alarms

Revision 1 proposed `signal.alarm`-based timeouts. That is rejected: alarms fire only in the main thread of
the main interpreter, cannot interrupt long-running C code (`ast.parse`, tree-sitter, the `re` engine) until it
returns to the interpreter, and `ast.parse` can crash the interpreter outright on deep nesting (Python `ast`
docs). The only reliable bound is a separate process that the supervisor can kill (SR-03, SR-09).

### 5.2 Worker model

- **Supervisor-owned pool, not `multiprocessing.Pool`.** The supervisor spawns N workers (default
  `min(cpu_count, 8)`, configurable) with the `spawn` start method, assigns **one file at a time** to each
  worker, and records the assignment before dispatch. Worker death is therefore always attributable to a
  specific file (threat-model §9 item 3).
- **Per-file wall-clock limit** (default 10 s parse + IR): enforced by the supervisor. On expiry the worker
  receives `SIGKILL` (POSIX) / `TerminateProcess` (Windows); the file is recorded as `timeout`; a fresh worker
  is spawned. No in-process cancellation is attempted.
- **Crash handling**: non-zero exit, signal, or EOF on the pipe ⇒ file recorded as `parser_crashed`; worker
  replaced. A file that kills two workers is not retried a third time.
- **Resource limits set in the worker before any untrusted byte is read** (POSIX `resource.setrlimit`):
  `RLIMIT_AS` (default 1 GiB; Linux — macOS does not enforce it reliably), `RLIMIT_CPU` (backstop slightly
  above wall-clock), `RLIMIT_FSIZE = 0` (workers write no files), `RLIMIT_NOFILE` small, `RLIMIT_CORE = 0`.
  On Linux the supervisor also polls `/proc/<pid>/statm` and kills a worker above the RSS cap. On macOS and
  Windows memory capping is best-effort (open risk R-3); the primary bound there is the pre-parse limits in §5.3.
- **IPC**: workers return results with `Connection.send_bytes`; the supervisor reads with `recv_bytes(maxlength)`
  and decodes **JSON** with a depth cap and schema validation. `pickle` is never used in the worker→supervisor
  direction, because a worker that parses hostile input is the most likely process to be compromised (SR-01).
- **Per-analysis limits**: the analysis worker (stage 7) runs under the same kill/rlimit regime with a global
  analysis wall-clock (default 300 s). Its *primary* bounds are deterministic budgets (iteration counts, path
  lengths, summary sizes — §8.6) so results are reproducible; wall-clock kill is a backstop. A budget hit or
  kill ⇒ `analysis_budgets_exhausted` / `analysis_timeout` ⇒ partial.
- Workers inherit no secrets they do not need: the environment passed to workers is reduced to locale and
  `NEXVUL_*` variables (T-19).

Process isolation contains crashes and hangs; it is **not** a security sandbox against memory-corruption
exploits in native parsers (T-28). OS-level sandboxing is a post-1.0 hardening item (open risk R-2).

### 5.3 Per-file limits (applied in this order; SR-04)

| Limit | Default | Configurable by | On hit |
|-------|---------|-----------------|--------|
| File size (checked via `lstat` before open) | 1 MiB | trusted sources; repo config may only lower (CI: §3.3) | `max_file_size` |
| Binary sniff (NUL in first 8 KiB, or undecodable) | — | no | `binary` / `non_utf8_undecodable` |
| Bracket/indent nesting estimate (token scan before `ast.parse`) | 100 | no | `max_nesting` |
| String-literal length kept in IR | 10,000 chars (truncated, flagged) | no | `literal_truncated` (does not make scan partial) |
| AST/CST node count | 500,000 | trusted sources | `max_ast_nodes` |
| Parse + IR wall-clock | 10 s | trusted sources | `timeout` |
| Worker RSS | 1 GiB | trusted sources | `memory_limit` |

All IR builders and walkers are iterative (explicit stack) or depth-guarded; `RecursionError` and
`MemoryError` are caught per file; `sys.setrecursionlimit` is never raised globally (SR-05).

### 5.4 Decoding and syntax version (SR-20, T-18, T-30)

- Python source is decoded exactly as CPython does (`tokenize.detect_encoding` semantics, BOM, PEP 263
  cookies); non-UTF-8 cookies, bidi controls and invisible format characters are reported as notes.
- `ast.parse` only accepts the grammar of the running interpreter. A file using newer syntax than the
  interpreter nexvul runs on fails to parse; this is recorded as `syntax_unsupported_by_runtime` (partial), and
  the docs recommend running nexvul on the newest supported CPython.
- Line/column computation uses one routine per language, consistent with CPython's tokenizer (Python) and
  tree-sitter byte offsets (JS/TS); SARIF declares `columnKind` explicitly (SR-29).

### 5.5 Regex discipline (T-07; SR-09)

Rules prefer AST/token matching. Any regex in nexvul is reviewed for linear-time behaviour (no nested
quantifiers; atomic groups/possessive quantifiers where needed, available in `re` since 3.11), is applied only to
bounded-length inputs, and is covered by a ReDoS fuzz meta-test that enumerates every `re.compile` call site.
Repo-local config cannot introduce regexes. The hard time bound is the worker kill above, never an alarm.

---

## 6. Language-neutral intermediate representation (IR)

### 6.1 Nodes

```
IRNode (base; frozen dataclass; id = (module_id, local_index))
  Module · FunctionDef · ClassDef · Parameter · CallSite · Assignment · Return · Import/Export
  Attribute · Subscript · Literal · BinaryOp/FormatString · Conditional · Loop · TryCatch
  Yield · Await · Decorator · Lambda/ArrowFunction · ObjectLiteral (JS/TS tool/agent configs)
```

Every node carries `(file, start_line, start_col, end_line, end_col)` and a language tag. Python and JS/TS
converters produce the same node kinds; language-specific semantics (Python MRO vs. JS prototypes, `self` vs.
`this`, CommonJS vs. ESM) are carried as tagged attributes, and rules may branch on language.

### 6.2 Facts (annotations added by recognisers and analyses)

```
SymbolRef        resolved reference (module/function/class/variable), with resolution status
                 {resolved, resolved_local_shadow, unresolved, dynamic}
AgentDecl        name, framework, tools[], memory, model, delegation_config, limits{}
ToolDecl         name, framework, sensitivity_class (S0–S8), annotations{}, description_ref
MemorySink       target_type (vector_store|long_term|checkpoint|conversation|db_memory),
                 persistence (persistent|session|ephemeral), store_identity, provenance_attached
MemorySource     store_identity, used_as (context|instruction|routing|data)
ControlFact      ApprovalGate | IterationLimit | Timeout | Allowlist | PolicyCheck | AuthCheck
CommChannel      protocol (http|grpc|mcp|a2a|direct), auth_present, identity_verified, tls
DangerousOp      category, scope (read|write|delete|execute)
FrameworkHint    framework, construct, resolved_version|range|unknown, evidence
McpEra           era (2024-11-05-legacy | 2025-session | 2026-07-28-stateless | unknown), evidence (§7.3)
AnalysisLimited  reason (dynamic_import|exec_of_computed|getattr_computed|unresolved_call), location
```

`store_identity` is an abstract location (resolved constructor call + constant collection/namespace
arguments) that lets a write site and a later read site of the same store be linked — this is what enables
second-order ASI06 flows (`web → memory.write … memory.read → system prompt`, NEX005).

### 6.3 Edges

`Calls · Imports · Exports/ReExports · Inherits · Delegates · HandsOffTo · UsesTool · WritesMemory ·
ReadsMemory · DataFlow · ControlFlow`.

### 6.4 Principles

- Immutable after construction; analyses add facts, never mutate nodes.
- Per-file IR is a pure function of (file bytes, repo-relative path, language, nexvul IR version, parser
  versions) — which is what makes it cacheable (§14) and reproducible.
- Cross-file resolution is a separate pass over the repo model (§7), never inside a parse worker.
- Strings from the scanned repo held in the IR are data; they are never interpreted, formatted as markup, or
  evaluated (T-23).

---

## 7. Repo model: modules, versions, framework recognition

### 7.1 Module map and import resolution

- **Python**: package roots inferred from layout (`src/` layout, `pyproject.toml` package config read as data,
  presence of `__init__.py`, namespace packages); absolute and relative imports; `from x import *` resolved
  via `__all__` when literal; aliases and re-exports tracked. An import whose target resolves to a **local**
  module that shadows a known framework name (`langchain`, `mcp`, …) is marked `resolved_local_shadow`, and
  framework recognisers do not treat it as the real framework (T-18 fake framework metadata).
- **JS/TS** (Phase 5): ESM `import`/`export` (named, default, namespace, re-export, `export *`), CommonJS
  `require`/`module.exports`, relative specifier resolution with extension/`index` probing, `tsconfig.json`
  `baseUrl`/`paths` and workspace `package.json` `exports` read as data. Dynamic `import(expr)` with non-literal
  argument ⇒ `AnalysisLimited`.

### 7.2 Dependency and version facts (lockfiles, read as data)

Framework defaults change between versions, so severity sometimes depends on the resolved version. Example
(source-verified in `docs/research/frameworks/README.md` §2): LangGraph's `recursion_limit` default is **25**
up to 1.0.5, **10000** in 1.0.6 and **10007** on main, while the docs claim 1000. A rule about unbounded graph
recursion therefore cannot be correct without knowing the version.

- Parsed in workers as manifests (size caps, safe loaders, no resolution, no install, no network):
  `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, pinned `requirements*.txt`, `pyproject.toml`
  constraints; `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `package.json` ranges.
- Output: `FrameworkVersion(framework, exact | range | unknown, evidence_files[])`. Conflicting evidence
  (two lockfiles disagree) ⇒ the union range.
- A **versioned defaults table** (data, with a source citation and test per row) maps `(framework, version
  range) → default limits/approval settings`. Rules query it; they never hard-code defaults.
- When the version is unknown, or the range spans rows with different defaults, the finding states both
  values and the uncertainty ("default is 25 in ≤1.0.5 and 10000 in ≥1.0.6; installed version not
  determined"), and confidence is capped at **medium** (detection-taxonomy §3.2).
- Lockfiles are attacker-controlled. A lockfile can change the wording/severity of a finding but never
  suppress it; version evidence is shown in the finding so a reviewer can see what it relied on.

### 7.3 Framework recognisers

- One module per framework (LangChain, LangGraph, CrewAI, AutoGen/AG2, OpenAI Agents SDK, LlamaIndex, Vercel
  AI SDK, MCP, A2A). Recognisers emit facts and **taint specs as data** keyed by resolved symbol, never by
  bare name (brief §5.6).
- **MCP spec eras.** Two current revisions must both be recognised (`docs/research/protocols/mcp.md` §1):
  - *2025-11-25* (session era): `initialize` handshake, `Mcp-Session-Id`, GET SSE stream, Dynamic Client
    Registration; Python SDK 1.x (`mcp.server.fastmcp.FastMCP`), TS `@modelcontextprotocol/sdk` v1.
  - *2026-07-28* (stateless): no `initialize`, `server/discover`, server-minted state handles, required
    `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name` headers, DCR deprecated in favour of CIMD; Python SDK 2.x
    (`mcp.server.MCPServer`), TS `@modelcontextprotocol/server` v2.
  - The recogniser emits `McpEra` from import paths and SDK version facts. Rules are era-aware: legacy-era
    markers (SSE transport, sessions, DCR) are informational at most; "session hijacking" checks apply to the
    2025 era and "state-handle used as authentication" checks to the 2026 era. Unknown era ⇒ only checks valid
    in both eras run. Names marked `UNVERIFIED` in the research are not hard-coded until confirmed.
- MCP client configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` with top-level `servers`,
  `claude_desktop_config.json`) are recognised by filename **and** structure, parsed as JSON/JSONC data only.

---

## 8. Taint engine (aimed at cross-file ASI06)

### 8.1 Goal

The differentiator (competitors README: "No tool has cross-file taint analysis") is connecting flows like the
brief §5.14 example:

```
web.py     def fetch(url): return requests.get(url).text          # source -> return
memory.py  def save(c): store.add_texts([c])                       # param 0 -> persistent sink
agent.py   save(fetch(u))                                          # composes the two summaries
```

### 8.2 Specifications are data

Sources, sinks, sanitisers and propagators are declared by rules and framework recognisers as typed specs
keyed by resolved symbols (e.g. `py:requests.get#return.text`, `py:langchain_core.vectorstores.VectorStore.add_texts#arg0`).
Each source carries a **label** (`http_response`, `tool_output`, `user_input`, `retrieved_content`,
`model_output`); each sink a **kind** (`persistent_memory`, `vector_index`, `system_instruction`,
`outbound_agent_message`, `privileged_tool_arg`) and persistence class from `MemorySink`.

### 8.3 Phases

| Phase | Scope | Roadmap |
|-------|-------|---------|
| T1 intra-procedural | locals, attributes, subscripts, f-strings, destructuring, `await`, basic collections | Phase 2 (slice) |
| T2 function summaries | per function: `param_i → return`, `param_i → sink(kind)`, `source(label) → return`, `param_i → attr/global`, sanitiser applied on path | Phase 3 |
| T3 cross-file | summaries applied across resolved imports; bottom-up over call-graph SCCs | Phase 3 (flag-gated until the benchmark shows a gain, roadmap Phase 3) |
| T4 store-linked flows | write to `store_identity` X + read from X used as instruction ⇒ second-order ASI06 | Phase 3/4 |
| T5 JS/TS | same engine over JS/TS IR; promise `.then`, callbacks, object-literal tool `execute` | Phase 5 |

### 8.4 Algorithm

- Per-file IR and **local** summaries (functions whose callees are all local or spec'd) are computed in parse
  workers and are cacheable (§14).
- The analysis worker builds the call graph, condenses SCCs, and computes summaries bottom-up; within an SCC it
  iterates to a fixpoint with widening. Access paths are k-limited (default k = 3); collections are modelled
  coarsely (taint on any element taints the collection).
- Each taint fact carries its **evidence chain** (file/line/label per step) so the finding's `dataflow` array
  can span files (§12.1).

### 8.5 Lattice and precision stance

`Tainted(labels, chain) ⊔ Clean ⊔ Unknown`. nexvul is **precision-biased**: an unresolved call does not
propagate taint (no summary ⇒ no flow). To stay honest about what that costs, each unresolved call on an
otherwise-tainted path increments `unresolved_calls_on_tainted_paths` and may emit an `AnalysisLimited` note;
a `--recall` mode is a later, opt-in option. Confidence follows the taxonomy: intra-procedural, catalogue APIs,
no unresolved calls ⇒ high; summaries/cross-file ⇒ medium (detection-taxonomy §3.2).

### 8.6 Budgets (deterministic; T-06)

Max fixpoint iterations per SCC, max summary size, max chain length, max SCC size analysed precisely
(larger SCCs fall back to "no flow" + `AnalysisLimited`), max total facts. Budgets are counts, not times, so the
same input gives the same output. Any exhausted budget is reported in completeness and makes the scan
**partial** (T-22).

---

## 9. Capability model (ASI10)

ASI10 rules score **combinations** of capabilities reachable from one agent's tools (brief §5.10): shell, code
execution, credential access, financial ops, network, filesystem write/read, database, delegation, tool
selection, memory write. Controls that reduce the score: approval gate, iteration limit, timeout, tool
allowlist, delegation limit, sandbox (including MCP client `sandboxEnabled`), policy engine, audit log.

```
risk = sum(capability_weight) × product(control_factor)
```

The revision-1 weights (shell 8 … FS read 2; no-controls 2.0, approval 0.5, sandbox 0.6, iteration limit 0.8)
are retained **as uncalibrated placeholders**; they must be calibrated on the benchmark before any ASI10 rule
ships (detection-taxonomy NEX020 "scoring weights need benchmark calibration"). Findings are phrased as
"missing containment", never "rogue agent detected".

## 10. Graph model (ASI08)

Directed graph of agents, tools, graph nodes and external endpoints with edges `delegates`, `hands_off_to`,
`calls`, `triggers`, `graph_edge` (LangGraph `add_edge`/`add_conditional_edges`, AutoGen speaker transitions,
CrewAI delegation, OpenAI Agents handoffs). Analyses: SCCs (Tarjan, O(V+E)) for cycles; guard search on cycle
paths (counter in state, conditional edge to END, framework limit from the versioned defaults table §7.2);
retry loops without stop/backoff; transitive fan-out. A cycle is reported only when no guard is found on it.

---

## 11. Rules

### 11.1 Rule structure

```python
@rule(
    id="NEX002", name="External content indexed into a vector store",
    owasp=["ASI06"], severity=Severity.HIGH, confidence_ceiling=Confidence.HIGH,
    cwe=["CWE-20"], detection_class="flow",
)
class ExternalContentToVectorStore(TaintRule):
    sources = [Source("py:requests.get#return", label="http_response"), ...]
    sinks = [Sink("py:langchain_core.vectorstores.VectorStore.add_documents#arg0", kind="vector_index"), ...]
    sanitisers = [...]
    message = ("Content returned by {source} reaches {sink} without an identified validation or "
               "trust-boundary check")
    remediation = "..."
```

Rule types: `TaintRule`, `PatternRule` (AST/IR patterns, not regex), `ConfigRule` (literal values, with the
versioned defaults table), `GraphRule`, `CompositeRule`. `help`/`fullDescription` text comes only from
reviewed rule docs in the package, never from scanned content (SR-12).

### 11.2 OWASP labels

`owasp` is an ordered list; the first element is the primary category. Multi-labelling ASI09/ASI10 rules
(e.g. NEX016 `["ASI02", "ASI09"]`, NEX020 `["ASI10", "ASI05"]`) follows `docs/owasp/mapping.md` and is a
**recommended default [pending human approval — Q1/Q2 in open-questions-security.md]**. The schema supports a
single label without change if the decision goes the other way.

### 11.3 Registry: built-in only until after 1.0 (T-25; SR-22)

- Rules are registered from a **frozen internal table** (`nexvul/rules/_registry.py`) generated at build time.
  nexvul does **not** call `importlib.metadata.entry_points()` and does not load any code from other installed
  distributions. A malicious package co-installed in the same environment therefore gets no hook into nexvul.
- At startup the registry's rule-ID list and the SHA-256 of the rule-pack content are computed and compared to
  the values baked in at build time; mismatch ⇒ exit 4 (detects monkeypatching). The rule-pack hash is printed
  in every output (SR-27).
- Config can enable/disable built-in rules only (subject to §3.3).

### 11.4 Later plugin model (post-1.0, design constraints only) [pending human approval — D8]

1. **Declarative rule packs first.** A pack is data (YAML/JSON) in nexvul's own spec language: sources, sinks,
   sanitisers, IR patterns, messages, OWASP labels. No code, no `eval`, and no regexes unless a linear-time
   engine is approved. Packs are loaded only from paths given via CLI or user config, pinned by SHA-256, never
   from repo config.
2. **Code plugins, if ever**, are full-trust Python. They load only from an explicit allowlist of
   (distribution name, exact version, wheel hash) given via CLI or user config; never auto-discovered; never
   from repo config; listed with versions in every output; and the threat model must be revisited first.
3. Every loaded pack/plugin appears in completeness `plugins_loaded` and in SARIF `tool.extensions`.

### 11.5 Suppressions (T-17; SR-17)

- Inline form `# nexvul: ignore[NEX001] reason="…"` (`//` for JS/TS), parsed from real comment tokens
  (`tokenize` COMMENT / tree-sitter comment nodes), never by regex over raw text. A rule ID is mandatory;
  blanket and file-level suppressions are not supported. Suppressions containing bidi/invisible characters are
  ignored and flagged.
- Suppressed findings are **still emitted** (JSON `suppressed: true` with justification; SARIF
  `result.suppressions[]` with `kind: "inSource"`) and counted in completeness.
- In CI mode, a suppression without `reason` is not honoured **[pending human approval — D2]**.
- Suppressions on lines changed in the PR are listed separately as `introduced_in_diff` **[pending human
  approval — D3]**. nexvul does not run `git diff`; the Action computes a changed-lines manifest in its own
  step and passes it as a trusted input file (`--changed-lines PATH`).

### 11.6 Rule tests and fixture convention (brief §2, §18; test-strategy §4)

Revision 1's example fixture `test_positive_001.py` would be **collected and executed by pytest**, violating
"never execute scanned code". Replaced by:

- Fixtures are stored with a **non-importable extension**: `case_<nnn>_<slug>.py.fixture`,
  `.ts.fixture`, `.js.fixture`, `.json.fixture`, `.yaml.fixture`. Python cannot import them and pytest never
  collects them.
- Cross-file cases are directories (`case_014_crossfile/web.py.fixture`, `memory.py.fixture`,
  `agent.py.fixture`).
- The harness strips `.fixture` and feeds the bytes to nexvul's in-process API as a **virtual tree**
  (`scan_virtual({ "web.py": b"..." , ...})`) — no fixture is ever written to disk with an executable
  extension inside the pytest rootdir.
- Defence in depth: `pyproject.toml` sets `[tool.pytest.ini_options] python_files = ["test_*.py"]`,
  `norecursedirs` including `tests/rules` and `benchmarks`, and `tests/conftest.py` sets `collect_ignore_glob`
  for the same trees. A meta-test fails the build if any file under `tests/rules/` or `benchmarks/` has a bare
  `.py/.js/.ts/.mjs/.cjs` extension or is named `conftest*`.
- Benchmark cases use the same convention; real-world corpus repos are fetched at pinned commits into a temp
  directory **outside** the repository and pytest rootdir, and are only ever read.
- Annotations are unchanged: `# nexvul-expect: NEX001 line=15`, `# nexvul-expect-not: …`,
  `# nexvul-known-miss: …`.

File `tests/rules/NEX002/positive/case_001_requests_to_add_documents.py.fixture`:

```text
# nexvul-expect: NEX002 line=4
import requests
content = requests.get(url).text
vector_store.add_documents([Document(page_content=content)])
```

(Line numbers in annotations refer to the fixture file's own lines; line 4 is the sink.)

---

## 12. Findings, completeness and exit codes

### 12.1 Finding schema (extends brief §10)

```json
{
  "schema_version": "1.0.0",
  "rule_id": "NEX002",
  "title": "External content indexed into a vector store",
  "severity": "high",
  "confidence": "medium",
  "owasp": ["ASI06"],
  "cwe": ["CWE-20"],
  "file": "agent/memory.py", "line": 42, "column": 8, "end_line": 42, "end_column": 45,
  "message": "Content returned by requests.get() reaches vector_store.add_documents() without an identified validation or trust-boundary check",
  "fingerprint": "sha256:…",
  "partial_fingerprints": {"primaryLocationLineHash": "…"},
  "dataflow": [
    {"step": 1, "file": "agent/web.py",    "line": 23, "label": "source", "description": "External content fetched from URL"},
    {"step": 2, "file": "agent/memory.py", "line": 41, "label": "call",   "description": "Passed to save() parameter c"},
    {"step": 3, "file": "agent/memory.py", "line": 42, "label": "sink",   "description": "Stored in vector store"}
  ],
  "evidence": [{"type": "no_sanitiser", "description": "No validation found between source and sink"}],
  "version_facts": [{"framework": "langchain-core", "version": "unknown", "evidence": []}],
  "untrusted_fields": ["dataflow[].snippet", "evidence[].snippet"],
  "suppressed": false,
  "limitations": ["Cannot determine at runtime whether the URL is restricted to trusted domains"],
  "remediation": "…",
  "references": ["…"]
}
```

- Snippets (when present) are length-capped and secret-redacted (SR-24) and listed in `untrusted_fields` so
  downstream LLM agents can segregate attacker-controlled text (T-23).
- `fingerprint` = SHA-256(rule_id, normalised path, normalised flow signature, normalised sink context);
  stable under whitespace/comment edits above the finding, distinct for distinct flows (test-strategy §5.3).
- The JSON schema is versioned with semver and shipped in the package (`nexvul/schemas/`); no `$schema` URL is
  fetched at runtime (SR-23).

### 12.2 Run metadata (SR-27, T-29)

Every output carries: nexvul version; rule-pack hash; Python version; parser/grammar versions; effective config
with per-key source and config file hashes; plugins loaded (empty before 1.0); start/end timestamps; scan roots
(repo-relative only in JSON/SARIF); target commit (from `.git/HEAD` as data, or supplied by the Action).

### 12.3 Completeness block (mandatory; threat-model §7; SR-18)

Computed by the normaliser from the supervisor's ledger — never from rule output. Schema as in threat-model §7,
extended with `scope` (`repository | explicit-paths`), `tracked_missing_on_disk`, `submodule_not_scanned`,
`syntax_unsupported_by_runtime`, `analysis_timeout`, `cache_entries_rejected` (informational) and
`unresolved_calls_on_tainted_paths` (informational).

`status`:
- **complete** — every discovered, in-scope regular file was parsed and analysed with no limit, budget,
  timeout, crash or truncation. Exclusions by trusted config do not make a scan partial (they are counted).
- **partial** — any file skipped for size, binary-with-source-extension, nesting, node count, timeout, crash,
  memory, decode failure, unsupported syntax; any global cap hit; any analysis budget exhausted or analysis
  timeout; findings truncated; git index unreadable.
- **failed** — the scan could not produce results (internal error, startup guard tripped).

Presentation rules:
- Terminal: when not complete, the **last** line, from trusted strings, is
  `PARTIAL SCAN — N of M files not analysed. This result is not a clean bill of health.` It is never
  suppressed by `--quiet`. "No findings" is printed only for complete scans and always reads
  "No findings from enabled rules. This does not prove the application is secure."
- JSON: required top-level `completeness`.
- SARIF: `invocations[0].executionSuccessful = false` when not complete; one
  `toolExecutionNotifications[]` per skip reason; `toolConfigurationNotifications[]` for weakened config; full
  block in `runs[0].properties.nexvul.completeness`.
- HTML: a non-dismissable banner at the top.

### 12.4 Exit codes (SR-19, T-20) — public contract once released

| Code | Meaning |
|------|---------|
| 0 | scan **complete** and no unsuppressed finding at/above `fail_on` |
| 1 | scan **complete** and ≥ 1 unsuppressed finding at/above `fail_on` |
| 2 | usage or configuration error (nothing scanned) |
| 3 | scan **partial** (regardless of findings; findings are still reported) |
| 4 | internal error / scan failed / startup guard tripped |

Precedence: 2 > 4 > 3 > 1 > 0. A partial scan is never exit 0. The default is that exit 3 **fails CI**
[pending human approval — D4]; trusted config/CLI (`--partial=warn`) may map partial to the findings-based code
(0/1), and that downgrade is itself recorded in the output. Repo-local config cannot set `--partial=warn`.

---

## 13. Reporters (T-10..T-13, T-20, T-24; SR-10..SR-13)

- **One sanitiser** (`reporting/sanitise.py`) for every untrusted string in every format: escape C0/C1, ESC,
  DEL, bidi and other Cf characters; cap length with ellipsis + hash suffix; encode non-UTF-8 paths reversibly
  (percent-encoding for SARIF URIs plus `raw_path_b64`); never emit lone surrogates; all outputs valid UTF-8
  (SR-10).
- **Terminal (Rich)**: untrusted text only via `rich.text.Text` objects (no markup parsing, no `highlight`, no
  emoji substitution); colour only on a TTY without `NO_COLOR`; with colour off the output contains zero ESC
  bytes; the summary/completeness block is printed last from trusted strings (SR-11, T-11).
- **JSON**: schema-validated in tests; repo-derived strings only in designated fields (§12.1).
- **SARIF 2.1.0**: rule `help`/`fullDescription` from built-in docs only; results use `message.text` only, never
  `message.markdown`; URIs repo-relative with `uriBaseId: "%SRCROOT%"`, no scheme, no `..`; the writer enforces
  GitHub's documented limits itself, sorting by severity before truncating and recording truncation in
  completeness (SR-12, T-20; limits re-checked at implementation time).
- **HTML (self-contained)**: a single file with no external fetches (no CDN, fonts, images, analytics); every
  untrusted string HTML-escaped by one context-aware routine for text nodes and quoted attribute values only —
  untrusted text is never placed in URLs (`href`/`src`), `style`, event handlers or script; embedded data, if
  any, goes in `<script type="application/json">` with `<`, `>`, `&`, U+2028/U+2029 escaped; a restrictive CSP
  meta tag (`default-src 'none'`; hashed inline style/script only; `img-src data:`; `base-uri 'none'`;
  `form-action 'none'`); built with stdlib `html.escape` and a small in-house builder rather than a template
  engine unless D7 approves one with autoescape; non-dismissable partial banner; "clean ≠ secure" statement
  (SR-13, T-13). Verified by a headless-browser XSS suite (test-strategy §5.4). SR-13 is a release blocker for
  any version that ships HTML.

---

## 14. Cache (T-09, T-21; SR-07, SR-08) — Phase 3 onward

Revision 1 placed the cache at `.nexvul/cache/` inside the scanned repo. That let an attacker commit a forged
entry keyed by the hash of a malicious file so that nexvul loads benign IR and never parses it (T-21), and it
collided with `.nexvul/` as the agent workspace (brief §4). Replaced by:

- **Location**: the per-user cache directory only — `$XDG_CACHE_HOME/nexvul` or `~/.cache/nexvul` (Linux),
  `~/Library/Caches/nexvul` (macOS), `%LOCALAPPDATA%\nexvul\Cache` (Windows) — or `--cache-dir` from CLI/user
  config/Action input. Repo config cannot set it. If the resolved cache dir lies inside any scan root, caching
  is disabled for the run and this is reported. Directory mode 0700, files 0600, created with `O_EXCL |
  O_NOFOLLOW`; parents checked for symlinks (SR-07).
- **Layout**: `<cache>/v<ir_schema>/<repo_key>/<aa>/<entry_key>.json`, where `repo_key` = SHA-256 of the
  canonical real path of the scan root (keeps repos separate and easy to evict), and `entry_key` =
  SHA-256(file content ‖ repo-relative path ‖ language ‖ nexvul version ‖ IR schema version ‖ parser and
  grammar versions ‖ Python version ‖ hash of analysis-relevant config ‖ rule-pack hash).
- **Untrusted on read**: each entry is JSON wrapped with an HMAC-SHA256 tag computed with a per-user random
  32-byte key (`<cache>/key`, 0600, created once with `O_EXCL`). On read: size cap → HMAC verify → JSON parse
  with depth cap → schema validation → the embedded content hash must equal the hash nexvul just computed from
  the file it read itself. Any failure ⇒ entry discarded, file re-parsed, `cache_entries_rejected` incremented
  (does not make the scan partial, because the file is re-analysed). The cache can only skip work, never
  substitute for reading the file (nexvul always reads and hashes every in-scope file).
- **What is cached**: per-file IR and local summaries only. Cross-file summaries and rule results are
  recomputed every run in v1.
- **CI**: the Action passes `--no-cache` by default; teams that opt in must not restore caches across trust
  levels (security-model "Safe CI usage" rule 6).
- Format is JSON only; no `pickle`, `marshal`, `shelve` (SR-01).

---

## 15. Performance (brief §15)

- Parse each file once; per-file IR is the unit of parallelism and caching.
- Parse workers run in parallel (§5.2); the analysis worker is single-process in v1 (simpler determinism);
  intra-procedural passes inside it can be parallelised later behind the same budgets.
- Lazy framework recognition: recognisers run only on modules whose resolved imports include their framework
  (or on manifests matching their structure).
- Rule indexing: rules declare the fact kinds/specs they need; the engine evaluates a rule only on modules that
  have them.
- Bounded memory: per-file IR is compacted (interned strings, integer node IDs); finding caps per file (100)
  and total (10,000) with truncation counted in completeness.
- Benchmarks at 100 / 1,000 / 5,000 / 10,000 files record runtime, CPU, peak RSS and findings
  (benchmark-strategy). Worker spawn cost and JSON IPC overhead are expected costs of SR-03 and will be
  measured, not assumed; nothing here is a performance claim.

---

## 16. Security-requirement traceability

| SR | Where satisfied |
|----|-----------------|
| SR-01 no execution/unsafe deserialisation | §5.2 JSON IPC, §6.4, §11.3, §14; CI lint for banned APIs |
| SR-02 no import from scan root | §2.1–2.2 |
| SR-03 worker isolation, deaths recorded | §5.2 |
| SR-04 limits, bounded reads | §4.3, §5.3 |
| SR-05 bounded recursion | §5.3 |
| SR-06 regular files, no symlink escape, TOCTOU | §4.3 (with the §4.2 `.git/index` carve-out — needs threat-model amendment) |
| SR-07 output/cache paths, atomic writes | §2.3, §3.2, §14 |
| SR-08 cache outside root, HMAC, keyed | §14 |
| SR-09 regex discipline, no alarms | §5.1, §5.5 |
| SR-10/11/12/13 output safety | §13 |
| SR-14 pre-commit `--`, path validation | §2.3 |
| SR-15 tighten-only CI config | §3.3 |
| SR-16 tracked files regardless of ignore | §4.1–4.2 |
| SR-17 suppressions | §11.5 |
| SR-18/19 completeness, exit codes | §12.3–12.4 |
| SR-20 decoding, analysis-limited notes | §5.4, §6.2 `AnalysisLimited` |
| SR-21 Action hardening | §2.1 (install/invoke); rest owned by DevSecOps |
| SR-22 plugins | §11.3–11.4 |
| SR-23 no network | §12.1 (no schema fetch), §18 dependency policy; socket-blocking test harness |
| SR-24 redaction, no absolute paths | §12.1, §13 |
| SR-25 LLM features | none in v1; any future feature is a new ADR + threat-model revision |
| SR-26 release pipeline | DevSecOps (out of this doc) |
| SR-27 run metadata | §12.2 |
| SR-28 config loading | §3.2 |
| SR-29 positions | §5.4 |
| SR-30 hostile fixtures in CI | test-strategy §7, §10 |

---

## 17. Package layout

```
nexvul/
  __main__.py            isolated-startup guard + re-exec (§2.2); imports only sys/os before the check
  cli/                   main.py (scan, precommit, rules, explain, doctor, version), args.py (path validation)
  core/
    startup.py           module-origin assertion (SR-02)
    config/              loader.py, schema.py, trust.py (tighten/loosen directions), defaults.py
    discovery/           walker.py, gitindex.py (bounded .git/index reader), policy.py
    workers/             supervisor.py, worker_main.py, limits.py (rlimits), ipc.py (JSON framing)
    ledger.py            completeness accounting
    cache.py             per-user, HMAC (§14)
    errors.py
  ir/                    nodes.py, facts.py, edges.py, builder.py, walk.py (iterative)
  parser/
    python/              decode.py (PEP 263), prescan.py (nesting estimate), parser.py, to_ir.py
    javascript/          parser.py (tree-sitter), to_ir.py           (Phase 5)
    typescript/          grammar selection for .ts/.tsx              (Phase 5)
    manifests/           json_safe.py, yaml_safe.py, toml_safe.py, lockfiles.py, mcp_config.py
  analysis/
    symbols.py  imports.py  callgraph.py  cfg.py
    taint/               specs.py, lattice.py, intra.py, summaries.py, crossfile.py, budgets.py
    graphs/              agent_graph.py (ASI08), capabilities.py (ASI10)
    versions.py          FrameworkVersion facts + versioned defaults table loader
  frameworks/            base.py, registry.py, langchain.py, langgraph.py, crewai.py, autogen.py,
                         openai_agents.py, llamaindex.py, vercel_ai.py, mcp/{eras.py, python.py, ts.py, configs.py}, a2a.py
  data/                  defaults_table/*.json (cited), sensitivity_catalogue/*.json
  rules/                 base.py, _registry.py (frozen), engine.py, suppressions.py, asi06/ … asi10/
  reporting/             sanitise.py, normaliser.py, terminal.py, json_reporter.py, sarif.py, html.py
  schemas/               finding/v1.json, completeness/v1.json
```

## 18. Dependency policy

Runtime (each subject to brief §32.4 review): CPython ≥ 3.12 stdlib; `click` or `typer`; `rich`; `pyyaml`
(safe loaders only); `tree-sitter` + grammar wheels (Phase 5; native code — T-28). Candidates pending D7:
git-index reader library (vs. in-house), `platformdirs` (vs. ~30 lines in-house), HTML template engine (vs.
in-house builder). No network, ML, database or scanner libraries at runtime; no Node.js. Dev-only: pytest,
pytest-cov, pytest-timeout, hypothesis, mypy, ruff, a socket-blocking plugin, actionlint/zizmor (pending
approval). Lockfiles hash-pinned (`--require-hashes`); SBOM per release (SR-26).

---

## 19. Decisions (P1-P5 accepted 2026-10-08, see DEC-0004 and DEC-0005)

| # | Decision | Decided policy | Section |
|---|----------|---------------------|---------|
| P1 (D1) | Repo-local config in CI | Tighten-only from PR head; loosening only from base branch or explicit workflow input; all weakenings listed | §3.3 |
| P2 (D2/D3) | Inline suppressions in CI | Justification required in CI; suppressions on PR-changed lines listed as `introduced_in_diff`; suppressed findings always emitted | §11.5 |
| P3 (D4) | Partial scans in CI | Exit 3 fails CI by default; only trusted config/CLI may downgrade to warn | §12.4 |
| P4 (D8) | Plugins | None before 1.0 (built-in frozen registry); afterwards declarative packs first, code plugins only by explicit allowlist | §11.3–11.4 |
| P5 (Q1/Q2) | ASI multi-labelling for ASI09/ASI10 rules | Ordered multi-label list, primary first, per `docs/owasp/mapping.md` | §11.2 |

P1-P4 are recorded in `.nexvul/decisions/DEC-0004`, P5 in `DEC-0005`. Related but not new: D5 (tracked files regardless of `.gitignore`) is adopted as the default in §4; D7
(git-index reader, `platformdirs`, HTML builder) remains open.

## 20. Open risks

| ID | Risk | Mitigation / status |
|----|------|---------------------|
| R-1 | Native parsers (tree-sitter grammars, PyYAML C loader) are a memory-safety surface; process isolation contains crashes, not exploits | OS sandboxing post-1.0; hash-pinned wheels; fuzzing in Phase 8 |
| R-2 | Worker isolation is same-user; a compromised worker can still act as the user | JSON-only IPC; reduced env; future seccomp/landlock/sandbox-exec |
| R-3 | Memory caps unreliable on macOS (`RLIMIT_AS`) and need Job Objects on Windows | Pre-parse size/nesting caps are the primary bound; documented per OS |
| R-4 | `ast.parse` accepts only the running interpreter's grammar | Recorded as partial (`syntax_unsupported_by_runtime`); evaluate tree-sitter-python fallback (ADR-0001) |
| R-5 | Precision bias (no flow through unresolved calls) causes false negatives | Counted and reported; benchmark measures recall; opt-in recall mode later |
| R-6 | `.git/index` carve-out from SR-06 | Bounded reader in a worker-equivalent sandbox; threat-model amendment requested |
| R-7 | Lockfiles are attacker-controlled and can change severity wording | Never suppress; version evidence shown in findings |
| R-8 | Spawn + JSON IPC overhead at 10k files | Measured in Phase 1 baseline; batching per worker allowed if attribution is preserved |
| R-9 | Capability weights uncalibrated | No ASI10 rule ships before benchmark calibration |
