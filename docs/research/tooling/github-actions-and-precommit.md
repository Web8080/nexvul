# GitHub Actions & pre-commit — Research Notes for nexvul

> Last updated: 2026-10-08. Sources: GitHub docs (actions/creating-actions),
> pre-commit.com, prek docs.

## GitHub Actions: Action Types

### Composite Actions

- **Definition:** Bundle multiple workflow steps into a reusable `action.yml`
- **Runtime:** Runs directly on the runner (no container overhead)
- **Platform:** All runners (Linux, macOS, Windows)
- **Startup:** Instant (no build step)
- **Complexity:** Can call other actions, run shell commands, use `if` conditions
- **Limitation:** Cannot use `services` or `container` keywords

```yaml
# action.yml
name: 'nexvul Scan'
description: 'Static security scanner for AI-agent applications'
inputs:
  fail-on:
    description: 'Minimum severity to fail (low|medium|high|critical)'
    default: 'high'
runs:
  using: 'composite'
  steps:
    - run: pip install nexvul
      shell: bash
    - run: nexvul scan . --format sarif --output results.sarif --fail-on ${{ inputs.fail-on }}
      shell: bash
    - uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: results.sarif
        category: nexvul
```

### Docker Actions

- **Runtime:** Runs inside a Docker container
- **Platform:** Linux runners only
- **Startup:** Slower (build or pull image)
- **Isolation:** Full environment control (OS, deps, Python version)
- **Use case:** When exact environment reproducibility matters

### JavaScript/Node Actions

- **Runtime:** Node.js on the runner
- **Platform:** All runners
- **Startup:** Fast
- **Packaging:** Must bundle dependencies (e.g., with `@vercel/ncc`)
- **Use case:** Actions that need to interact with the GitHub API

### Recommendation for nexvul

**Composite action.** Reasons:
1. nexvul is a Python CLI — `pip install` + `nexvul scan` is the simplest path
2. Cross-platform (users may scan on macOS/Windows runners too)
3. No Docker build overhead
4. No Node.js packaging complexity
5. Users can see and understand the steps

A Docker action could be offered later for pinned-environment reproducibility,
but the composite action is the primary distribution.

## Marketplace Requirements

To publish on GitHub Marketplace, an action must:

1. **Be in a public repository**
2. **Have `action.yml` (or `action.yaml`) at the repository root**
3. **One action per repository** (for Marketplace listing)
4. **Unique name** — cannot match existing Marketplace actions or user/org names
5. **Required metadata:**
   - `name` — display name
   - `description` — what the action does
   - `author` — maintainer
   - `branding.icon` — from the Feather icon set
   - `branding.color` — one of: white, yellow, blue, green, orange, red,
     purple, gray-dark
6. **No workflow files** in the repository (for auto-listing)
7. **Developer agreement** accepted on first publish (browser-based)

### nexvul Marketplace Strategy

Two options:
- **Dedicated action repo** (`nexvul/nexvul-action`) — clean Marketplace listing
- **Subdirectory in main repo** (`.github/actions/nexvul/`) — simpler maintenance
  but won't auto-list on Marketplace

Recommendation: Start with subdirectory for development, publish to a
dedicated repo for Marketplace release.

## pre-commit Hook

### Manifest File (`.pre-commit-hooks.yaml`)

The manifest lives at the repository root and defines available hooks:

```yaml
- id: nexvul
  name: nexvul security scan
  entry: nexvul scan
  language: python
  types: [python]
  pass_filenames: true
  description: 'Static security scanner for AI-agent applications'
  minimum_pre_commit_version: '2.9.0'
```

### Required Fields

| Field | Description |
|---|---|
| `id` | Stable hook identifier (e.g., `nexvul`) |
| `name` | Display name shown during hook execution |
| `entry` | Command to run |
| `language` | Runtime environment (`python`, `node`, `system`, etc.) |

### Key Optional Fields

| Field | Default | Description |
|---|---|---|
| `pass_filenames` | `true` | Pass matching staged files as CLI args |
| `files` | `''` | Regex filter for filenames |
| `exclude` | `'^$'` | Regex to exclude filenames |
| `types` | `[file]` | File type filter (e.g., `[python]`, `[javascript]`) |
| `types_or` | `[]` | OR-combined type filter |
| `stages` | `[pre-commit]` | Git hook stages |
| `args` | `[]` | Additional arguments |
| `additional_dependencies` | `[]` | Extra packages to install |
| `require_serial` | `false` | Prevent parallel execution |
| `always_run` | `false` | Run even if no matching files |
| `verbose` | `false` | Show hook output even on success |

### Staged Files Behaviour

- pre-commit passes only **staged** files (files in the git index)
- Files are filtered by `files`, `exclude`, `types`, and `types_or`
- If `pass_filenames: true`, matching filenames are appended to `entry`
- If `pass_filenames: false`, the hook runs once with no file arguments
- Hooks see the **staged version** of files (via stash), not the working
  directory version

### nexvul pre-commit Configuration

User's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nexvul/nexvul
    rev: v0.1.0
    hooks:
      - id: nexvul
        args: ['--fail-on', 'high']
        types_or: [python, javascript, ts, yaml, json]
```

### Design Considerations

1. **`pass_filenames: true`** — nexvul should accept file paths as positional
   args and scan only those files. This is critical for pre-commit performance
   (don't re-scan the entire repo on every commit).

2. **Multi-language scanning** — Use `types_or: [python, javascript, ts]`
   to match all supported languages. Need to also include YAML/JSON for
   config files (`.nexvul.yml`, MCP configs, agent manifests).

3. **Exit codes:**
   - 0 = no findings above threshold
   - 1 = findings above threshold (blocks commit)
   - 2+ = scanner error (also blocks commit)

4. **Performance** — pre-commit hooks must be fast. Consider:
   - Skip cross-file analysis in pre-commit mode (only staged files available)
   - Cache parsed ASTs
   - Limit to single-file rules by default
   - Offer `--full` flag for complete analysis

5. **Incremental mode** — When `pass_filenames` is true, nexvul receives
   only changed files. It should still load cached context (symbols, imports)
   for cross-file rules if available.
