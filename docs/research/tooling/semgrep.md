# Semgrep — Research Notes for nexvul

> Last updated: 2026-10-08. Sources: Semgrep docs, Semgrep engineering blog, PyPI.

## Rule Model

Semgrep rules are YAML files with a pattern-matching DSL. Each rule specifies:

- `id`, `message`, `severity` (ERROR / WARNING / INFO / INVENTORY), `languages`
- **Pattern operators:** `pattern`, `patterns` (AND), `pattern-either` (OR),
  `pattern-not`, `pattern-inside`, `pattern-not-inside`, `pattern-regex`
- **Metavariables:** `$X` captures bind to AST nodes, not text. Metavariable
  comparisons (`metavariable-comparison`, `metavariable-regex`,
  `metavariable-pattern`) add constraint power.
- **Fix suggestions:** `fix` / `fix-regex` for auto-remediation.

Rules are language-aware and match on the concrete syntax tree, not raw text.
Semgrep supports ~30 languages via tree-sitter grammars internally.

## Taint Mode

Taint mode is declared per-rule with `mode: taint` and specifies:

- `pattern-sources` — where tainted data originates
- `pattern-sinks` — where tainted data must not reach
- `pattern-sanitizers` — where taint is removed
- `pattern-propagators` — custom propagation (e.g., `collection.append(item)`)

### OSS vs Pro Capabilities

| Capability | OSS | Pro |
|---|---|---|
| Intra-procedural taint (single function) | Yes | Yes |
| Intra-file cross-function taint | Limited | Yes |
| **Inter-file / cross-file taint** | **No** | **Yes** |
| **Inter-procedural analysis** | **No** | **Yes** |
| Function summaries | No | Yes |
| Additional languages (Apex, C#, Elixir) | No | Yes |

**Key limitation for nexvul:** Semgrep OSS cannot track data flow across files.
Cross-file analysis (e.g., `web.py: fetch()` -> `memory.py: store()`) requires
Pro. Pro runs with `-j 1` for cross-file analysis (single-threaded per ruleset).

### 2026 Engine Improvements (Pro)

Semgrep Pro engine 1.158.0 (June 2026) redesigned taint analysis:
- P95 scan times dropped from 10 minutes to 7:30
- Some large repos saw 3x+ improvements
- The older approach built a "naming environment" to resolve cross-file
  function references; the new engine optimises this path.

## What to Borrow for nexvul

### Borrow

1. **Taint-as-data model.** Sources/sinks/sanitizers/propagators declared
   declaratively per rule. This is elegant and testable. nexvul should adopt
   a similar pattern where taint specifications are data, not imperative code.

2. **Metavariable binding.** Binding captured AST subtrees to named variables
   enables expressive constraints without writing visitor code. nexvul's rule
   DSL should support something equivalent.

3. **Propagator concept.** Explicit propagators for collection operations
   (`list.append`, `dict[key] = val`) solve a common taint-tracking gap.
   nexvul needs this for `memory.add_documents()`, `vector_store.upsert()`.

4. **Severity model.** ERROR/WARNING/INFO is simple but Semgrep adds
   `confidence` in its registry metadata. nexvul already has
   severity + confidence in the brief.

5. **Rule testability.** Semgrep rules are tested with inline annotations
   (`# ruleid: ...`, `# ok: ...`) in test files. nexvul should adopt a
   similar convention for rule regression tests.

### Do Not Borrow

1. **Pattern DSL tied to concrete syntax.** Semgrep patterns match surface
   syntax, which means rules are language-specific. nexvul's IR-based approach
   should allow some rules to be language-neutral.

2. **Single-file OSS limitation.** nexvul must do cross-file analysis from
   day one for agent security (agent definitions, tool registrations, and
   memory operations typically span files). Building our own is necessary.

3. **Tree-sitter dependency for all languages.** Semgrep uses tree-sitter
   internally. nexvul uses Python `ast` for Python (more accurate, type-aware
   in stdlib) and tree-sitter only for JS/TS.

## Licence

Semgrep OSS engine: LGPL-2.1. Rules registry: mixed (many are proprietary).
Pro engine: proprietary. nexvul cannot use Semgrep's Pro engine or proprietary
rules. The OSS engine's architecture is instructive but nexvul builds its own.
