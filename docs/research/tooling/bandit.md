# Bandit — Research Notes for nexvul

> Last updated: 2026-10-08. Sources: PyCQA/bandit repo, PyPI, Real Python.

## Overview

Bandit is the standard Python security linter. Originally developed by
OpenStack Security Project, now maintained under PyCQA. It finds common
security issues in Python code using AST analysis.

## Plugin Model

### Architecture

```
File → Python ast.parse() → AST → Node Visitor → Plugin Dispatch → Issues
```

Bandit processes each file independently:
1. Parse the file with `ast.parse()`
2. Walk the AST with a node visitor
3. For each node type, dispatch to registered plugins
4. Collect `bandit.Issue` results
5. After all files: aggregate and format output

### Plugin Registration

Plugins register via the `@bandit.checks` decorator, specifying which AST
node type they handle:

```python
@checks('Call')
def unsafe_yaml_load(context):
    if context.call_function_name_qual in ['yaml.load', 'yaml.unsafe_load']:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text="Use of unsafe YAML loader"
        )
```

Entry points: `bandit.plugins` (checks) and `bandit.formatters` (output).
Third-party packages can register plugins via setuptools entry points.

### Node Types

Plugins can register for:
- `Call` — function/method calls (most common)
- `Import` / `ImportFrom` — import statements
- `Str` — string literals (for hardcoded secrets, etc.)
- `Exec` — exec/eval usage
- `FunctionDef` — function definitions

## Confidence and Severity

Each `bandit.Issue` carries two independent ratings:

| Level | Severity | Confidence |
|---|---|---|
| LOW | Minor concern | Possible but uncertain |
| MEDIUM | Moderate risk | Probable |
| HIGH | Serious vulnerability | Near certain |

**Severity** reflects the potential impact if exploited.
**Confidence** reflects how certain Bandit is that the finding is real.

Users filter with CLI flags:
- `-l` / `-ll` / `-lll` — minimum severity (LOW/MEDIUM/HIGH)
- `-i` / `--confidence` — minimum confidence level

### Scoring

Bandit computes per-file severity and confidence scores by summing the
levels of all findings in each file. This is used for ranking, not for
individual finding assessment.

## Limitations

1. **Single-file only.** No cross-file analysis, no import resolution,
   no call graph, no data flow.

2. **Pattern matching, not semantic analysis.** Checks function names and
   AST structure, but doesn't track values, types, or data flow.

3. **No taint tracking.** Cannot trace `user_input → dangerous_call`.
   Each check is a point-in-time AST pattern match.

4. **Name-based detection.** Relies on function names matching expected
   patterns. Aliases, wrappers, and dynamic dispatch defeat it.

5. **No framework awareness.** Doesn't understand Django, Flask, or any
   framework's security model.

## What to Borrow for nexvul

### Borrow

1. **AST visitor dispatch pattern.** Registering handlers for specific AST
   node types is clean and extensible. nexvul's IR visitors should follow
   a similar dispatch model.

2. **Severity + confidence dual rating.** This is already in nexvul's brief
   (§10). Bandit validates that the model works in practice.

3. **Entry-point plugin system.** Setuptools entry points allow third-party
   rule packages. nexvul should support a similar extension mechanism for
   community rules.

4. **CLI filtering.** Users need to filter by severity and confidence at
   the command line. Bandit's `-l` / `-i` flags are a reasonable UX model.

5. **Profile/test selection.** Bandit's `-t` (include) and `-s` (skip)
   flags for test IDs map to nexvul's `rules.enabled` / `rules.disabled`
   config.

### Do Not Borrow

1. **Single-file limitation.** Agent security requires cross-file analysis.
   Bandit's architecture fundamentally cannot support this.

2. **Name-only matching.** `yaml.load` detection by string matching is too
   brittle for agent frameworks where the same concept has many names.

3. **Flat issue model.** Bandit issues lack data-flow paths, evidence
   chains, and remediation specificity. nexvul's finding model (§10) is
   richer by design.

4. **No IR / no intermediate representation.** Bandit works directly on
   the Python AST. nexvul needs a language-neutral IR to support both
   Python and JS/TS.
