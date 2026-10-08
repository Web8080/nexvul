# Handoff: Phase 1, step 1 (skeleton, limits, completeness, config, discovery)

| Field | Value |
|-------|-------|
| Author | Implementation engineer (agent) |
| Date | 2026-10-08 |
| Scope | Package skeleton, self-protection limits, completeness ledger + exit codes, `.nexvul.yml` loader + DEC-0004 policy, discovery. **No analysis, parsers, rules, taint or reporters.** |
| Commits | None made by this agent (see "Repository state" below) |

## 1. What was built

| Path | Contents |
|------|----------|
| `pyproject.toml` | Python >= 3.12, src layout, console script `nexvul`, pinned dev deps, pytest (`norecursedirs` for fixture trees, 60 s `pytest-timeout` on every test), ruff (Python files only), mypy strict. Licence left unset with a TODO. |
| `src/nexvul/__init__.py` | `__version__ = "0.0.1.dev0"` |
| `src/nexvul/__main__.py` | Imports only `sys`/`os`; if neither `-P` nor `-I` is active, re-execs `python -P -E -m nexvul ...`; a marker env var makes a second re-exec fail closed (exit 4). |
| `src/nexvul/cli/main.py` | click group with `version` and `-h/--help` only. Usage errors exit 2, unexpected exceptions exit 4 with no traceback, Ctrl-C exits 130. |
| `src/nexvul/core/limits.py` | Named constants with documentation (config 64 KiB/depth 8/20k events; file size 1 MiB default, 16 MiB hard; max_files 50k default, 200k hard; depth 64; 1M dir entries; 2 GiB total; 120 s discovery budget; git index 128 MiB / 1M entries / 4 KiB paths). |
| `src/nexvul/core/completeness.py` | `Completeness` ledger (scanned/failed/timed-out/skipped, `skipped_by_reason`, capped path list, limits hit, notes), `SkipReason` with an impact class for each reason (partial/counted/info), `ExitCode`, `resolve_exit_code` (2 > 4 > 3 > 1 > 0, OD-06), trusted partial-as-warning downgrade. |
| `src/nexvul/core/config.py` | Loader: `O_NOFOLLOW` open, `fstat` regular-file and size check before reading, bounded read, strict UTF-8, YAML **event pass** that rejects anchors, aliases, explicit tags, `%TAG`, multiple documents, depth and event floods. Construction uses a `SafeLoader` subclass that rejects duplicate, non-string and merge keys. Strict schema with unknown-key rejection. Path confinement for `exclude`. Per-key source tracking. `resolve_config()` is a pure function applying DEC-0004 §1. |
| `src/nexvul/core/discovery.py` | Walker based on fds (`openat` chain with `O_NOFOLLOW` for every component, directory dev/inode re-check, regular files only, `O_NONBLOCK`, `fstat` re-check, 8 KiB NUL sniff), bounded in-house `.git/index` reader (v2-4, SHA-1/SHA-256 detected from the trailer), `.git/HEAD` read as data, tracked-file pass, exclude-pattern matcher without regex, language detection, every exclusion counted. Returns `DiscoveryResult`; never prints. |
| `src/nexvul/core/sanitize.py` | The single display sanitiser for untrusted strings (controls, C1, ESC, bidi/Cf, separators, surrogate-escaped bytes, confusable slashes/dots, backslash; truncation with hash suffix). Reporters must reuse it. |
| `src/nexvul/core/startup.py` | `assert_no_module_from_roots()` module-origin check (SR-02). |
| `tests/` | 350 tests collected (348 pass, 2 skip on macOS). Unit tests for each module, security tests named by MF id, an audit-hook and canary execution test, and meta-tests (fixture naming, banned APIs). |

## 2. Design choices

- **Every path is opened relative to an already-open directory fd** with `O_NOFOLLOW`. A path therefore cannot resolve outside the root, even when a directory is swapped for a symlink mid-scan (MF-54 tests cover file→symlink, file→other inode, dir→symlink, dir→other dir, and FIFO swapped in after lstat). This also handles paths longer than PATH_MAX (MF-21, MF-65).
- **`follow_symlinks` never reads through a link.** It only resolves the target as a path to report `symlink_escapes_root` versus "target inside root; scanned at its own path". Directory links are never traversed. This is stricter than architecture §4.3 and removes loop and duplicate risk entirely.
- **Malformed git index means the whole index is rejected.** Discovery falls back to directory mode, the scan is marked partial (`git_index_unreadable`), and paths from a bad index are never opened. The reader rejects `..`, absolute paths, empty or `.` components, any `.git` component (case-insensitive), entry counts over the cap or larger than the file can hold, bad checksums, v2 entries with extended flags, and v4 prefix strips longer than the previous name. The object format comes from the trailer, so `.git/config` is never read.
- **Tracked files outside the walk** are found by a second pass that re-opens each one through the fd chain. Examples are tracked files in default-excluded `node_modules/`.
- **Exclude patterns** are matched by an iterative wildcard matcher with no regex (SR-09). A pattern without `/` matches any path component. A pattern with `/` is anchored at the root and matches everything below. `**` spans directories, and a trailing `/` matches directories only.
- **DEC-0004 resolution:** trusted layers (defaults, then base ref, user and CLI layers) apply in full. Each loosening from a trusted layer is listed with status `applied`. The repo layer applies in full locally and every loosening is listed as `applied`. In CI only its tightening changes apply, and each loosening becomes a `ConfigChange` with status `not_applied`, displayed as "NOT APPLIED". Set-valued keys use replace semantics. In CI: `enabled` = trusted ∪ head, `disabled` = trusted ∩ head, `exclude` = trusted ∩ head.
- **Config errors never echo values.** Attacker-controlled key names go through the sanitiser.

## 3. Doc conflicts and open questions (for the Supervisor)

1. **Package layout.** Architecture §17 uses packages (`core/config/`, `core/discovery/`, `core/ledger.py`). The task asked for flat modules (`core/config.py`, `core/discovery.py`, `core/completeness.py`), and I followed the task. I added `core/sanitize.py`; architecture puts the sanitiser at `reporting/sanitise.py`. It can move when reporters land, as long as there is still one sanitiser.
2. **Name of the partial downgrade flag.** DEC-0004 §3 says `--allow-partial`; architecture §12.4 says `--partial=warn`. It is implemented as the parameter `partial_is_warning`. The CLI flag name must be decided in step 2.
3. **Weakening status vocabulary.** Architecture §3.3 uses `ignored`/`applied`; the task says "NOT APPLIED". I implemented `not_applied`, displayed as "NOT APPLIED". The JSON schema in step 2 must pick one.
4. **`analysis.max_file_size`.** §5.3 says "repo config may only lower", and §3.3 classes lowering a limit as loosening. Taken together, PR-head config can never change it in CI, and repo config can never raise it in any mode. Implemented exactly that way.
5. **Repo config raising `max_files`** is "tighten" per §3.3, but it is also a resource-exhaustion vector (T-05). It is bounded by `HARD_MAX_FILES = 200,000`. Please confirm.
6. **MF-108 / T-16 vs architecture §4.1.** The test plan and the T-16 residual expect a `.gitignore` fallback in plain directories, but architecture §4.1 says ignore files are not honoured by default. I implemented the architecture behaviour: everything is scanned. The MF-108 test asserts that and its docstring records the conflict. Related: **gitignore matching for untracked files in git mode is not implemented**, so untracked ignored files are scanned. That gives more coverage but may be noisier. Linear-time ignore matching (MF-42) remains to be done.
7. **`rules.enabled` vs `rules.disabled` across layers.** Within one file, listing a rule in both is an error. Across layers, a rule can end up in both sets (for example, base disables X and head enables X without touching `disabled`). The rule engine needs a precedence decision, and in CI "enabled wins" is the tighter choice.
8. **Excluded directories are counted once per directory.** This applies to default and config exclusions. Their contents are not enumerated, to keep `node_modules` from exhausting the entry budget. Tracked files inside are still classified one by one.
9. **`.git/HEAD`.** Symbolic refs are not resolved, because that would need `.git/refs`, which SR-06 forbids. A commit SHA is reported only for a detached HEAD.

## 4. Commands run and outcomes (2026-10-08, macOS 26.2 arm64)

| Command | Outcome |
|---------|---------|
| `python3.12 -m venv .venv` | **Failed.** Homebrew 3.12.14 is broken on this machine: `pyexpat` has a missing symbol, and inside the sandbox `platform.mac_ver()` is empty, which breaks pip's truststore. |
| `python3.13 -m venv .venv` | OK (Python 3.13.12) |
| `.venv/bin/python -m pip install -e ".[dev]"` | OK (PyYAML 6.0.3, click 8.5.0, pytest 9.1.1, pytest-cov 7.1.0, pytest-timeout 2.4.0, coverage 7.16.2, ruff 0.16.10, mypy 2.4.0, types-PyYAML 6.0.12.20260906) |
| `.venv/bin/nexvul version` / `--help` / no args / `bogus` | exit 0 / 0 / 2 / 2 |
| `.venv/bin/pytest --cov=nexvul --cov-branch --cov-report=term` | **348 passed, 2 skipped**, 3.6 s |
| `.venv/bin/ruff check .` | All checks passed |
| `.venv/bin/ruff format --check .` | 26 files already formatted |
| `.venv/bin/mypy --strict src` | Success: no issues found in 11 source files |

Coverage of `core/` (combined line and branch from coverage.py): completeness 100%, config 97%, discovery 94%, limits 100%, sanitize 95%, startup 100%; package total 96%. **Discovery is just below the test-strategy floor of 95% line / 90% branch.** The uncovered lines are mostly race-only error paths (for example `.git` lstat failure, or the index growing between `fstat` and read). Subprocess runs of `python -m nexvul` are not counted in coverage.

Skipped, not run on this machine (must run on Linux CI):
- MF-25 (case collision: APFS is case-insensitive)
- MF-64 (non-UTF-8 filenames: APFS rejects them)

The display side of MF-64 is unit-tested on bytes. MF-51 runs on macOS, but there is no `/proc`, so its "not read" assertion is weak here.

Manual negative control: a generated `yaml.py` canary **does** fire under `python -c "import yaml"` with the hostile directory as CWD. This proves the canary payload works, so MF-06 passing is meaningful.

## 5. Known gaps

- **Python 3.12 is untested at runtime.** The suite ran on 3.13 only; mypy checks 3.12 typing, but no 3.12 run took place.
- Discovery needs POSIX (`O_NOFOLLOW`, `dir_fd`). **Windows is unsupported.**
- The wall-clock budget is checked at each directory and every 256 entries. A single hung syscall (for example on NFS) is not interruptible; the hard bound is worker isolation in a later step.
- MF scale-downs for PR speed:
  - MF-20: 2,000 files with a cap of 100, not 1M.
  - MF-21: depth 120, not 5,000.
  - MF-10: a sparse 3 GB file is used, not a real one.
- Network blocking is an in-house monkeypatch (`connect`, `connect_ex`, `create_connection`, `getaddrinfo`), not `pytest-socket`.
- No Hypothesis property tests yet; that dependency is not approved (test-strategy §12).
- There is no hash-pinned lockfile (`--require-hashes`). Dev pins are exact versions only.
- `nexvul.egg-info/` is created under `src/` by the editable install. It is gitignored (`*.egg-info/`).
- MF cases outside this step's scope are not implemented: parse stage (MF-12/13/15-19), writes (MF-57/58/60), reporters (MF-61 output side, MF-70+), suppressions (MF-110+), CI/Action, cache and plugins.

## 6. Repository state

While I was working, files I had just written (`pyproject.toml` and most of `src/nexvul/`) were **committed by another session** in commits `d2d6959` and `cd11a21` (DEC-0010/DEC-0011 commits). Those snapshots are mid-work versions. The working tree now has later edits to them, and `tests/` is untracked. I made no commits and did not push. Before committing, review the full diff (`git diff -- src pyproject.toml`) together with `tests/`.

## 7. Inputs for step 2

- The `scan` command must, in this order:
  1. Parse args and validate roots.
  2. Call `startup.assert_no_module_from_roots(roots)` (exit 4 on a hit).
  3. Load the repo config with `config.load_repo_config(root)` (exit 2 on `ConfigError`) and trusted layers (`--config-base`, user config, CLI).
  4. Call `resolve_config(ci=ci_mode_from_env(os.environ) or --ci)`.
  5. Call `discover(root, DiscoveryOptions(max_files=..., max_file_size=..., exclude=...))`.
- Workers must re-open each `DiscoveredFile` with `O_NOFOLLOW`, relative to an fd chain, and verify `(device, inode)` before parsing.
- Reporters must render the completeness block (`Completeness.to_dict()`), `ResolvedConfig.changes` as `protections_weakened_by_repo_config`, and `config_sources` with SHA-256 hashes. Every path and key must go through `sanitize.display_text` / `display_path`.
- Decide the items in §3 (flag names, status vocabulary, enabled/disabled precedence, gitignore for untracked files).
- Set up Linux CI so that MF-25, MF-51 and MF-64 actually execute.
