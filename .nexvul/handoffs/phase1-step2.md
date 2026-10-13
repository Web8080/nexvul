# Handoff: Phase 1, step 2 (IR, Python parser, worker isolation)

| Field | Value |
|-------|-------|
| Author | Implementation engineer (agent) |
| Date | 2026-10-13 |
| Scope | Language-neutral IR, Python front end (ast -> IR), process-isolated parse workers folded into the completeness ledger. **No CLI wiring, reporters, rules or taint.** |
| Commits | None (not asked to commit) |

## 1. What was built

| Path | Contents |
|------|----------|
| `src/nexvul/ir/model.py` | Frozen dataclasses, schema `IR_SCHEMA_VERSION = "0.1.0"`: `Location`, `SymbolRef` (written / resolved / `ResolutionStatus` imported, local, instance, builtin, unresolved, dynamic), `ExprSummary` (bounded, **non-recursive** expression summary with constant value/type and referenced names), `Keyword`, `CallSite`, `ImportRecord`, `Decorator`, `Parameter`, `FunctionDecl`, `ClassDecl`, `Assignment` (`=`, `+=`, `:`, `:=`), `ReturnFact`, `StringConstant` (capped), `AnalysisLimited`, `ParseFailure`, `ModuleIR` (status, failure, sha256, encoding, column unit, node count, notes). `FailureReason` values equal `SkipReason` values. |
| `src/nexvul/ir/codec.py` | JSON encode (`ensure_ascii`, no NaN) and a **strict** decoder compiled once per type: exact key sets, exact primitive types (bool is not int), known enum values, schema major version, duplicate-key and NaN rejection, `RecursionError` from deep JSON mapped to `IRDecodeError`. Doubles as the supervisor's schema check of worker replies. |
| `src/nexvul/parser/python.py` | `parse_python(bytes, path) -> ModuleIR`, never raises. Order: decode as CPython (`tokenize.detect_encoding`, BOM, PEP 263) -> NUL check -> token-stream bracket+indent nesting estimate (100) -> `ast.parse(text, filename="<nexvul-target>")` -> iterative node count (500k) -> one iterative pre-order extraction walk with explicit stack. Resolves `import x as y`, `from a import b as c`, relative imports (path-derived package), builtins, local defs, simple intra-module binding (`m = ChatOpenAI(); m.invoke`, aliases, `with ... as`, `self.attr` across methods of one class), attribute chains, chained calls (`OpenAI().chat.completions.create`). Records decorators, kwargs, f-string names, walrus, match captures, async/await, annotations, lambdas/comprehension scopes, `AnalysisLimited` for exec/eval/compile, computed `__import__`/`importlib.import_module`/`getattr`, star imports and relative imports above the top. Notes: `bom`, `non_utf8_coding_cookie`, `bidi_control`, `invisible_format_character`. Newer-than-runtime syntax heuristic (t-strings, unparenthesised `except A, B`, type-param defaults) -> `syntax_unsupported_by_runtime`. |
| `src/nexvul/core/workers.py` | `analyse_files(root, files, *, options, completeness, worker_entry) -> AnalysisResult`. Supervisor-owned pool, `spawn` context, one file per worker at a time, per-file wall clock with `Process.kill()` (SIGKILL), crash retry once then `parser_crashed`, protocol violations not retried, JSON-only `send_bytes`/`recv_bytes(maxlength)`, reduced env at spawn and again in the child, worker hardening (stdio -> /dev/null, `RLIMIT_CORE=0`, `RLIMIT_FSIZE=0`, `RLIMIT_NOFILE<=64`, per-file `RLIMIT_CPU`, `RLIMIT_AS` Linux only), Linux `/proc/<pid>/statm` RSS kill, module-origin assertion in the worker per task (`WorkerStartupError` -> exit 4), workers re-open files through an `O_NOFOLLOW` fd chain and re-check `(dev, inode)`, size and regular-file type. Every input becomes exactly one `FileOutcome` and one ledger entry. |
| `src/nexvul/core/limits.py` | Added parse-stage limits (nesting 100, nodes 500k, literal 10,000 chars, expr render caps, timeout 10 s / hard 120 s, workers 8, worker memory 1 GiB, nofile 64, CPU margin 2 s, result cap 64 MiB, crash attempts 2, dotted name 1024). |
| `src/nexvul/core/completeness.py` | Added `SkipReason.PARSER_UNAVAILABLE` (partial) for in-scope languages with no parser yet (JS/TS/JSON/YAML/TOML before their phases). |
| Tests | `tests/unit/test_ir.py`, `tests/unit/test_parser_python.py`, `tests/unit/test_workers.py`, `tests/security/test_mf_parser.py`, `tests/security/test_mf_workers.py`, helper `tests/security/worker_faults.py` (fault-injecting worker entries; test-only `pickle` use to prove rejection). All hostile inputs are generated in `tmp_path`. |

## 2. Design choices

- **IR is facts, not a node graph.** Phase 1 records calls, imports, assignments, returns, declarations, literals and limits. The schema is non-recursive, so JSON depth is bounded by the schema, and decoding cannot recurse on hostile input.
- **Resolved names are dotted strings.** Instance resolution appends the attribute to the constructor (`langchain_openai.ChatOpenAI.invoke`), matching spec keys of the form `Class.method`. Calling an instance-bound name yields `...__call__`. Binding is flow-insensitive within a scope and in source order; rebinding to anything unknown drops the old binding (no stale resolution). Names longer than 1024 chars become `dynamic` rather than truncated.
- **Failure detail is trusted text only** (line numbers, limits). CPython messages are never copied, because they can echo source. `ast.parse` gets a fixed sentinel filename.
- **CPython's parser guards** map to typed reasons. `RecursionError` during AST construction, `MemoryError("... too complex ...")` from the parser stack, and tokenizer "too many nested/levels" all become `max_nesting`. Other `MemoryError` becomes `memory_limit`.
- **Supervisor decode cost:** a 1 MiB file at the cap produces an IR of about 18 MB. Measured in-process on this machine: parse+IR 2.0 s, encode 0.7 s, supervisor decode 0.85 s (2.0 s before the decoder was compiled per type).
- **Spawn bootstrap:** `multiprocessing` pickles the trusted `Process` object parent -> child and re-imports the parent's `__main__` as `__mp_main__`. For `python -m nexvul` that import is skipped; for the console script it imports nexvul's own guarded script. Results never use pickle. `-P` propagates to workers (verified: child `safe_path=True` when the parent runs with `-P`).
- **Env reduction** temporarily swaps `os.environ` around `Process.start()` (spawn inherits the C environment), then restores it. The supervisor must be single-threaded while it starts workers.

## 3. Doc conflicts and open questions

1. **Package layout:** architecture §17 vs this step's `ir/`, `parser/python.py`, `core/workers.py` (task layout followed).
2. **§6.1 says every node carries the file path;** here it is stored once on `ModuleIR`. Columns are CPython UTF-8 byte offsets (`column_unit = "utf8_bytes"`); reporters must convert for SARIF `columnKind` (SR-29).
3. **`parser_unavailable` is a new reason.** The architecture has none for "in-scope language without a parser". Treating JS/TS as `unsupported_file_type` (info) would make a scan with TS files "complete" while analysing nothing in them. Needs Supervisor sign-off.
4. **Bytes-level binary vs NUL later in the file:** a NUL after discovery's 8 KiB sniff is recorded as `parse_error` ("null byte in source"), not `binary`.
5. **`detect_newer_syntax` is a heuristic** covering three constructs. Any other newer syntax is recorded as `parse_error` (still partial).
6. **`memory_limit_enforced` is false on macOS.** The ledger gets a trusted note saying so. That is honest, but it puts a note on every macOS scan; the Supervisor may prefer to show it only in `doctor`.

## 4. Commands run and outcomes (2026-10-13, macOS 26.2 arm64, Python 3.13.12 venv)

| Command | Outcome |
|---------|---------|
| `pytest -q --cov=nexvul --cov-branch` | **530 passed, 2 skipped** (MF-25, MF-64: Linux-only, unchanged), ~27 s |
| `ruff check .` | All checks passed |
| `ruff format --check .` | 39 files already formatted |
| `mypy --strict src` | Success: no issues found in 17 source files |

Coverage (coverage.py JSON, new modules): `core/workers.py` 99.2% line / 96.9% branch; `parser/python.py` 98.1% / 97.5%; `ir/codec.py` 100% / 100%; `ir/model.py` 100%. **Caveat:** code that runs only inside the worker process is not measured in-process and is marked `pragma: no cover`: `_harden_process`, `_set_cpu_budget`, `worker_main`, and the CPU-limit branch in `serve`. Their effect is asserted from a spawned probe in `test_worker_hardening` (env, CORE, FSIZE, NOFILE; AS only on Linux). `serve`, `handle_task` and `read_file` are also unit-tested in-process.

## 5. Known gaps

- **Python 3.12 is still untested at runtime;** only 3.13 has run. Python 3.14 has not run either. The t-string test branches on the interpreter version.
- **Not run on Linux:** RLIMIT_AS and the real `/proc` RSS path. The RSS kill is tested with a monkeypatched reader.
- **MF-17 uses a simulated crash** (SIGSEGV from a fault worker), not a curated real CPython AST-compiler crash input.
- **No coverage of worker child processes.** `RLIMIT_FSIZE=0` would also block coverage data files.
- **Flow-insensitive binding:** a later reassignment inside a branch overrides earlier bindings. There is no class-attribute inheritance, no closure-captured rebinding, and no `global`/`nonlocal` semantics. `from x import *` binds nothing.
- **Path-derived module names** are not re-rooted for `src/` layouts; that belongs to the repo model (§7.1).
- **Supervisor-side IR decoding is single-threaded** (about 0.85 s per worst-case 1 MiB file). IR size is about 17x the source at worst.
- MF-12/18/19 (JS, JSON depth) are out of scope until those parsers exist.

## 6. Inputs for step 3 (reporters and `scan` command)

- `scan` order: startup guard -> config -> `discover(root, ...)` -> `analyse_files(result.root, result.files, options=WorkerOptions(max_file_size=..., timeout_seconds=..., max_workers=...), completeness=result.completeness)`. Pass the **same** ledger so discovery skips and parse outcomes combine. Catch `WorkerStartupError` -> exit 4. Use `exit_code_for(ledger, ...)`.
- Reporters render `completeness.to_dict()` including the new `parser_unavailable`, `timeout`, `parser_crashed` counts and notes. Every IR string (paths, `written`, `text`, string literals) is untrusted and must go through `sanitize.display_text`/`display_path`.
- Rules consume `ModuleIR.calls` (`callee.resolved`, `keywords[].value.const_type/value`), `functions[].decorators`, `imports`, `assignments`, `strings`, `limited`.
- Decide §3 items 3 and 6, and the CLI flag for parse timeout and worker count (trusted sources only).
