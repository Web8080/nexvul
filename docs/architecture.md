# nexvul — Architecture

> Status: **Proposed** (Phase 0). No implementation exists yet.
> Owner: Principal Architect. Last updated: 2026-10-08.

## 1. Pipeline Overview

```
                                    nexvul scan .
                                         |
                          +--------------+---------------+
                          |         CLI / Config         |
                          |  (.nexvul.yml, CLI flags)    |
                          +--------------+---------------+
                                         |
                          +--------------v---------------+
                          |     Repository Discovery     |
                          |  gitignore, excludes, limits |
                          +--------------+---------------+
                                         |
                          +--------------v---------------+
                          |     Language Detection       |
                          |  extension, shebang, heuristic|
                          +--------------+---------------+
                                         |
                     +-------------------+-------------------+
                     |                                       |
          +----------v-----------+              +------------v----------+
          |   Python Parser      |              |  JS/TS Parser         |
          |   (ast module)       |              |  (tree-sitter)        |
          +----------+-----------+              +------------+----------+
                     |                                       |
                     +-------------------+-------------------+
                                         |
                          +--------------v---------------+
                          |    Intermediate Repr (IR)    |
                          |  Nodes, facts, relationships |
                          +--------------+---------------+
                                         |
                     +-------------------+-------------------+
                     |                   |                   |
          +----------v------+  +---------v--------+  +------v-----------+
          | Symbol Table &  |  | Call Graph        |  | Control Flow     |
          | Import Resolver |  | Builder           |  | Graph (CFG)      |
          +----------+------+  +---------+---------+  +------+-----------+
                     |                   |                   |
                     +-------------------+-------------------+
                                         |
                          +--------------v---------------+
                          |       Taint Engine           |
                          |  source -> propagation ->    |
                          |  sanitiser check -> sink     |
                          +--------------+---------------+
                                         |
                          +--------------v---------------+
                          |   Framework Recognisers      |
                          |  LangChain, LangGraph,       |
                          |  CrewAI, AutoGen, OpenAI SDK, |
                          |  MCP                         |
                          +--------------+---------------+
                                         |
                          +--------------v---------------+
                          |       Rule Engine            |
                          |  ASI06..ASI10 rules          |
                          +--------------+---------------+
                                         |
                          +--------------v---------------+
                          |    Finding Normaliser        |
                          |  dedup, fingerprint, rank    |
                          +--------------+---------------+
                                         |
                     +-------------------+-------------------+
                     |                   |                   |
          +----------v------+  +---------v--------+  +------v-----------+
          |  Terminal        |  |  JSON             |  |  SARIF           |
          |  Reporter        |  |  Reporter         |  |  Reporter        |
          +-----------------+  +------------------+  +------------------+
```

### Pipeline Stages

1. **Discovery** — Walk the repository respecting `.gitignore`, `.nexvul.yml`
   excludes, and per-file limits (size, symlink policy). Produce a file manifest
   with language tags.

2. **Parsing** — Language-specific parsers produce raw ASTs:
   - Python: `ast.parse()` from the standard library (full CPython AST)
   - JS/TS/JSX/TSX: `tree-sitter` with `tree-sitter-typescript` and
     `tree-sitter-javascript` grammars (CST, converted to nexvul IR)

3. **IR Construction** — Convert language-specific ASTs into the
   language-neutral Intermediate Representation (see §2).

4. **Symbol Resolution** — Build symbol tables, resolve imports across files,
   track aliases and re-exports.

5. **Call Graph** — Build an inter-procedural call graph from resolved symbols
   and call sites.

6. **CFG** — Build intra-procedural control-flow graphs for functions that
   contain taint-relevant operations.

7. **Taint Analysis** — Run the taint engine (see §3) using rule-declared
   sources, sinks, and sanitisers.

8. **Framework Recognition** — Identify framework-specific patterns
   (LangChain agents, MCP tool declarations, etc.) and annotate the IR with
   semantic facts.

9. **Rule Evaluation** — Rules query the enriched IR to produce raw findings.

10. **Normalisation** — Deduplicate, fingerprint, compute data-flow paths,
    rank by severity/confidence.

11. **Reporting** — Emit findings in the requested format(s).

---

## 2. Language-Neutral Intermediate Representation (IR)

The IR is the core data structure that all analysis operates on. It is
language-neutral: Python and JS/TS parsers both produce IR nodes.

### 2.1 Core Node Types

```
IRNode (base)
  ├── Module          — a source file
  ├── FunctionDef     — function/method definition
  ├── ClassDef        — class definition
  ├── CallSite        — a function/method call
  ├── Assignment      — variable/attribute assignment
  ├── Return          — return statement
  ├── Import          — import statement (resolved to target module)
  ├── Parameter       — function parameter
  ├── Attribute       — attribute access (obj.attr)
  ├── Subscript       — index/key access (obj[key])
  ├── Literal         — string/number/bool literal
  ├── BinaryOp        — binary operation
  ├── Conditional     — if/ternary/match
  ├── Loop            — for/while/async for
  ├── TryCatch        — try/except/catch
  ├── Yield           — yield/yield from/generator
  ├── Await           — await expression
  └── Decorator       — decorator application
```

### 2.2 Semantic Fact Types (Annotations on IR Nodes)

```
Fact (base)
  ├── SymbolRef       — resolved reference to a symbol (module, function, class, variable)
  ├── AgentDecl       — an agent declaration (framework-specific)
  │     fields: name, framework, tools[], memory, model, delegation_config
  ├── ToolDecl        — a tool/function exposed to an agent
  │     fields: name, framework, capabilities[], permissions[], description
  ├── MemorySink      — a write to persistent memory or vector store
  │     fields: target_type (vector_store|long_term|checkpoint|conversation),
  │              source_trust, validation_present
  ├── MemorySource    — a read from persistent memory
  │     fields: source_type, trust_level, used_as (context|instruction|data)
  ├── ControlFact     — a control/oversight mechanism
  │   ├── ApprovalGate    — human approval before action
  │   │     fields: action_type, gate_type (confirm|policy|hitl), scope
  │   ├── IterationLimit  — bound on loops/retries/delegation depth
  │   │     fields: limit_type (max_iterations|max_retries|max_depth), value
  │   └── Timeout         — time bound on execution
  │         fields: target (agent|tool|chain), duration
  ├── CommChannel     — inter-agent communication channel
  │     fields: protocol (http|grpc|mcp|a2a|direct), auth_present,
  │              identity_verified, trust_boundary
  ├── DangerousOp     — a sensitive/destructive operation
  │     fields: category (filesystem|network|shell|database|financial|credential),
  │              scope (read|write|delete|execute)
  └── FrameworkHint   — framework-specific metadata
        fields: framework, pattern_type, version_constraint
```

### 2.3 Relationships (Edges)

```
Edge (base)
  ├── Calls           — function A calls function B
  ├── Imports         — module A imports from module B
  ├── Inherits        — class A inherits from class B
  ├── Delegates       — agent A delegates to agent B
  ├── UsesTool        — agent uses tool T
  ├── WritesMemory    — code writes to memory M
  ├── ReadsMemory     — code reads from memory M
  ├── DataFlow        — data flows from node A to node B
  └── ControlFlow     — execution flows from A to B (with condition)
```

### 2.4 IR Design Principles

- **Immutable after construction.** IR nodes are frozen dataclasses. Analysis
  adds facts (annotations), never mutates nodes.
- **Source-mapped.** Every IR node carries `(file, line, column, end_line,
  end_column)` for finding locations.
- **Language-tagged.** Each module node carries its source language for
  language-specific rule behaviour.
- **Incrementally constructible.** Each file can be parsed and converted to IR
  independently. Cross-file resolution is a separate pass.

---

## 3. Taint Engine

### 3.1 Design

The taint engine tracks data flow from **sources** (where untrusted data enters)
through **propagation** (assignments, function parameters, returns, attributes,
collections) to **sinks** (where untrusted data causes harm), checking for
**sanitisers** (where taint is removed).

Sources, sinks, sanitisers, and propagators are declared as **data** by rules
and framework recognisers. The taint engine is generic.

### 3.2 Phased Implementation

**Phase 1: Intra-procedural (single function)**
- Track taint through local variables, assignments, and expressions
- Handle attribute access (`obj.data`), subscripts (`dict["key"]`)
- Handle `async`/`await` (taint flows through awaited values)
- Handle basic collections (`list.append()`, `dict[k] = v`)

**Phase 2: Function summaries (single file)**
- Compute summaries: "parameter 0 taints return value"
- Apply summaries at call sites within the same file
- Handle callbacks: if a tainted value is passed as a callback argument,
  the callback's return may be tainted

**Phase 3: Cross-file**
- Resolve imports and apply function summaries across module boundaries
- Handle re-exports and aliased imports
- Build a cross-file call graph for reachability

### 3.3 Taint Lattice

```
Tainted(source, path)   — data is tainted; carries provenance
Clean                    — data is known clean (sanitised)
Unknown                  — no information (conservative: treated as potentially tainted
                           only when flowing from a declared source)
```

**Soundness vs precision stance:** nexvul is **precision-biased**. We prefer
fewer false positives over fewer false negatives. An Unknown value does NOT
propagate taint — only explicitly declared sources do. This means nexvul will
miss some real vulnerabilities (false negatives) but findings it reports are
more likely to be real.

Rationale (brief §2): "noisy rules destroy trust."

### 3.4 Taint Through Language Constructs

| Construct | Handling |
|---|---|
| Assignment `x = tainted` | x becomes tainted |
| Attribute `obj.attr = tainted` | obj.attr tainted; obj itself tainted (conservatively) |
| Subscript `d[k] = tainted` | d[k] tainted; d tainted (conservatively) |
| Function call `f(tainted)` | Apply summary of f; if no summary, taint does NOT propagate (precision) |
| Return `return tainted` | Summary: return is tainted from parameter |
| Async/await `x = await f(tainted)` | Same as function call |
| Callback `map(tainted_list, fn)` | Propagators define how callbacks interact with taint |
| String formatting `f"{tainted}"` | Result is tainted |
| Collection spread `[*tainted]` | Result is tainted |
| Destructuring `a, b = tainted` | a and b are tainted |

### 3.5 Framework-Provided Taint Specifications

Framework recognisers register taint specifications:

```python
# Example: LangChain memory taint spec
TaintSpec(
    source=Pattern("requests.get($URL).text"),
    sink=Pattern("$MEMORY.add_documents($DOCS)"),
    sanitiser=Pattern("$SANITISER.validate($DATA)"),
    message="Content from {source} reaches {sink} without validation",
    rule_id="NEX001",
)
```

---

## 4. Capability Model (ASI10 — Rogue Agents)

ASI10 detection scores **combinations** of agent capabilities, not individual
ones. A single capability (e.g., shell access) is lower risk than the
combination of shell + network + no approval + unbounded iteration.

### 4.1 Capability Enumeration

```
AgentCapability:
  SHELL_ACCESS        — can execute shell commands
  FILESYSTEM_READ     — can read arbitrary files
  FILESYSTEM_WRITE    — can write/delete files
  NETWORK_ACCESS      — can make HTTP/network requests
  CREDENTIAL_ACCESS   — can access secrets/keys/tokens
  DATABASE_ACCESS     — can query/modify databases
  CODE_EXECUTION      — can execute arbitrary code
  DELEGATION          — can delegate to other agents
  TOOL_SELECTION      — can choose which tools to invoke
  MEMORY_WRITE        — can write to persistent memory
  FINANCIAL_OPS       — can perform financial operations
```

### 4.2 Control Enumeration

```
AgentControl:
  APPROVAL_GATE       — human approval before action
  ITERATION_LIMIT     — bounded loop/retry count
  TIMEOUT             — execution time limit
  TOOL_ALLOWLIST      — restricted set of available tools
  DELEGATION_LIMIT    — bounded delegation depth
  SANDBOX             — execution in restricted environment
  AUDIT_LOG           — actions are logged/monitored
  POLICY_ENGINE       — policy checks before execution
```

### 4.3 Risk Scoring

```
risk_score = sum(capability_weights) * control_deficit_multiplier

capability_weights:
  SHELL_ACCESS:      8
  CODE_EXECUTION:    8
  CREDENTIAL_ACCESS: 7
  FINANCIAL_OPS:     7
  NETWORK_ACCESS:    5
  FILESYSTEM_WRITE:  5
  DATABASE_ACCESS:   5
  DELEGATION:        4
  TOOL_SELECTION:    3
  MEMORY_WRITE:      3
  FILESYSTEM_READ:   2

control_deficit_multiplier:
  no controls:       2.0
  only logging:      1.5
  iteration limit:   0.8   (reduces multiplier)
  approval gate:     0.5   (reduces multiplier)
  sandbox:           0.6   (reduces multiplier)
  -- multipliers compound --
```

A high-capability agent with no controls produces a critical finding.
A high-capability agent with approval gates, iteration limits, and a
sandbox may produce no finding at all.

---

## 5. Graph Model (ASI08 — Cascading Failures)

ASI08 detection requires a **directed graph** of agent/tool interactions to
find cycles, unbounded chains, and missing safeguards.

### 5.1 Graph Construction

Nodes:
- Agent declarations
- Tool declarations
- External service endpoints

Edges:
- `agent --delegates--> agent`
- `agent --calls--> tool`
- `agent --calls--> external_service`
- `tool --triggers--> agent` (callback/webhook patterns)

### 5.2 Analysis

1. **Cycle detection:** Find strongly connected components (SCCs) in the
   delegation graph. Any SCC with >1 node is a potential infinite delegation
   loop. Tarjan's algorithm, O(V+E).

2. **Unbounded chain detection:** Find paths without iteration limits.
   Walk the graph from each agent; if a path of length > threshold has no
   `IterationLimit` or `Timeout` control fact, flag it.

3. **Retry storm detection:** Find tool calls inside retry loops without
   backoff or attempt limits.

4. **Fan-out analysis:** Count the number of agents/tools an agent can
   reach transitively. High fan-out without controls indicates blast radius.

---

## 6. Rule Plugin API

### 6.1 Rule Structure

```python
@rule(
    id="NEX001",
    name="Untrusted content to persistent memory",
    owasp=["ASI06"],
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    cwe=[CWE.IMPROPER_INPUT_VALIDATION],
    tags=["security", "memory-poisoning"],
)
class UntrustedContentToMemory(TaintRule):
    """Content from external sources reaches persistent memory without validation."""

    sources = [
        SourcePattern("requests.get($URL)", returns=True),
        SourcePattern("httpx.get($URL)", returns=True),
        SourcePattern("urllib.request.urlopen($URL)", returns=True),
        SourcePattern("BeautifulSoup($HTML)", returns=True),
    ]

    sinks = [
        SinkPattern("$MEMORY.add_documents($DOCS)", param="$DOCS"),
        SinkPattern("$VECTORSTORE.upsert($DATA)", param="$DATA"),
        SinkPattern("$MEMORY.save_context($CTX)", param="$CTX"),
    ]

    sanitisers = [
        SanitiserPattern("$VALIDATOR.validate($DATA)"),
        SanitiserPattern("sanitize($DATA)"),
    ]

    message = (
        "Content returned by {source} reaches {sink} without an identified "
        "validation or trust-boundary check"
    )

    remediation = (
        "Validate or sanitise external content before storing it in agent memory. "
        "Consider content-type checks, length limits, and provenance tagging."
    )
```

### 6.2 Rule Types

| Type | Base Class | Use Case |
|---|---|---|
| `TaintRule` | Declares sources/sinks/sanitisers | Data-flow vulnerabilities |
| `PatternRule` | Declares AST patterns to match | Structural issues |
| `GraphRule` | Queries the agent/tool graph | Architectural issues (ASI08, ASI10) |
| `CompositeRule` | Combines multiple sub-checks | Multi-factor scoring (ASI10) |

### 6.3 Rule Registration

Rules are discovered via:
1. **Built-in rules** in `nexvul/rules/{asi06,asi07,...}/`
2. **Entry points** (`nexvul.rules`) for third-party rule packages
3. **Config-driven enable/disable** via `.nexvul.yml`

### 6.4 Rule Testing

Each rule has test files in `tests/rules/{rule_id}/`:
- `positive/` — code that SHOULD trigger the rule (expected TP)
- `negative/` — code that should NOT trigger (expected TN)
- `edge_cases/` — boundary cases with documented expected behaviour
- `adversarial/` — evasion attempts (wrappers, aliases, indirection)

Test convention (inspired by Semgrep):
```python
# test_positive_001.py
# nexvul-expect: NEX001 line=15
content = requests.get(url).text     # line 15
memory.add_documents([content])
```

---

## 7. Finding Model

Extends brief §10 with fingerprints, data-flow steps, evidence, and limitations.

### 7.1 Finding Schema

```json
{
  "$schema": "https://nexvul.dev/schemas/finding/v1.json",
  "schema_version": "1.0.0",
  "rule_id": "NEX001",
  "title": "Untrusted content to persistent memory",
  "severity": "high",
  "confidence": "high",
  "owasp": ["ASI06"],
  "cwe": ["CWE-20"],

  "file": "agent/memory.py",
  "line": 42,
  "column": 8,
  "end_line": 42,
  "end_column": 45,

  "message": "Content returned by requests.get() reaches vector_store.add_documents() without an identified validation or trust-boundary check",

  "fingerprint": "sha256:a1b2c3d4e5f6...",
  "partial_fingerprints": {
    "primaryLocationLineHash": "39fa2ee980eb94b0:1"
  },

  "dataflow": [
    {
      "step": 1,
      "file": "agent/fetcher.py",
      "line": 23,
      "column": 12,
      "label": "source",
      "snippet": "content = requests.get(url).text",
      "description": "External content fetched from URL"
    },
    {
      "step": 2,
      "file": "agent/memory.py",
      "line": 42,
      "column": 8,
      "label": "sink",
      "snippet": "vector_store.add_documents([Document(page_content=content)])",
      "description": "Content stored in vector store without validation"
    }
  ],

  "evidence": [
    {
      "type": "source_call",
      "description": "requests.get() fetches arbitrary external content",
      "location": {"file": "agent/fetcher.py", "line": 23}
    },
    {
      "type": "no_sanitiser",
      "description": "No validation/sanitisation found between source and sink"
    }
  ],

  "limitations": [
    "Cannot determine if URL is restricted to trusted domains at runtime",
    "Does not analyse request headers or authentication"
  ],

  "remediation": "Validate or sanitise external content before storing in agent memory. Consider content-type checks, length limits, and provenance tagging.",

  "references": [
    "https://owasp.org/www-project-top-10-for-agentic-applications/ASI06",
    "https://nexvul.dev/rules/NEX001"
  ]
}
```

### 7.2 Fingerprinting

Findings are fingerprinted for deduplication across runs:

1. **`fingerprint`** — SHA-256 of `(rule_id, normalised_file_path,
   normalised_context_lines)`. Stable across whitespace-only changes.

2. **`partial_fingerprints.primaryLocationLineHash`** — for SARIF/GitHub
   compatibility. Hash of the content of the line and surrounding context
   (3 lines, whitespace-stripped).

### 7.3 JSON Schema Versioning

The finding schema is versioned with semver (`schema_version` field):
- **Major:** Breaking changes to required fields
- **Minor:** New optional fields added
- **Patch:** Documentation/description changes only

The schema is published at `nexvul/schemas/finding/v{major}.json` and
validated in CI.

---

## 8. Caching and Incremental Analysis

### 8.1 Content-Hash Keyed Cache

```
.nexvul/cache/
  files/
    {sha256_of_file_content}.ir.json     — cached IR for a file
    {sha256_of_file_content}.symbols.json — cached symbol table
  manifest.json                           — file path → content hash mapping
```

On re-scan:
1. Hash each file's content
2. If hash matches cache, load cached IR + symbols
3. If hash changed, re-parse and update cache
4. Invalidate cross-file analysis if any dependency changed

### 8.2 Cache Invalidation

A file's cache is invalidated when:
- Its content hash changes
- Any file it imports has its content hash changed (transitive)
- The nexvul version changes (IR format may differ)
- A rule's source/sink/sanitiser patterns change

### 8.3 Parallelism

- **File parsing:** Embarrassingly parallel. Use `multiprocessing.Pool`
  with process count = CPU cores (configurable).
- **Taint analysis:** Intra-procedural is per-function (parallel). Cross-file
  requires the full symbol table (sequential construction, parallel queries).
- **Rule evaluation:** Rules are independent; evaluate in parallel.

### 8.4 Memory Bounds

- **Per-file AST limit:** Skip files where `ast.parse()` / tree-sitter
  produces > 500,000 nodes. Log warning.
- **Total IR limit:** If total IR nodes exceed configurable limit (default:
  10,000,000), process files in batches and merge findings.
- **Finding limit:** Cap findings per file (default: 100) and total
  (default: 10,000) to prevent memory exhaustion on pathological repos.

---

## 9. Self-Protection

nexvul scans untrusted code. The scanner itself must be hardened.

### 9.1 Per-File Limits

| Resource | Default Limit | Configurable |
|---|---|---|
| File size | 1 MB | Yes (`analysis.max_file_size`) |
| AST depth | 200 levels | No |
| AST nodes | 500,000 | Yes (`analysis.max_ast_nodes`) |
| Parse time | 5 seconds | Yes (`analysis.parse_timeout`) |
| String literal length | 10,000 chars | No |

Files exceeding limits are **skipped** with a warning, not crashed on.

### 9.2 Symlink Policy

- **Default:** Do not follow symlinks. Resolve symlinks to detect
  directory escape, log and skip.
- **Configurable:** `discovery.follow_symlinks: true` (opt-in, with
  cycle detection).

### 9.3 No Network, No Code Execution

nexvul NEVER:
- Makes network requests during scanning
- Executes scanned code (`exec`, `eval`, `subprocess`, `importlib`)
- Imports scanned modules
- Runs scanned project's build scripts
- Processes scanned project's `package.json` scripts

### 9.4 Safe Loading

- **YAML:** Use `yaml.safe_load()` only. Never `yaml.load()`.
- **JSON:** Use `json.loads()` only. Never `eval()` on JSON strings.
- **TOML:** Use `tomllib` (stdlib) only.
- No `pickle`, `marshal`, or `shelve` on untrusted data.

### 9.5 ReDoS-Safe Regex

All regular expressions used in rules and parsers must be:
- Reviewed for catastrophic backtracking
- Tested with pathological inputs
- Subject to a match timeout (Python `re` with `re.match` + alarm signal,
  or `re2` library if available)
- Prefer possessive quantifiers and atomic groups where supported

### 9.6 Injection Prevention

- **ANSI escape codes:** Strip from all output written to SARIF or JSON.
  Only emit ANSI in terminal output when `stdout.isatty()`.
- **SARIF injection:** All string values in SARIF output are JSON-escaped.
  File paths, messages, and snippets from scanned code are sanitised.
- **Markdown injection:** `help.markdown` content is escaped to prevent
  injection into GitHub's rendering. No raw HTML in markdown output.
- **Filename safety:** File paths from scanned repos are validated (no null
  bytes, no control characters, no path traversal beyond repo root).

---

## 10. Package Layout

```
nexvul/
  __init__.py
  __main__.py              — entry point for `python -m nexvul`

  cli/
    __init__.py
    main.py                — Typer/Click app, commands
    config.py              — .nexvul.yml loading and validation
    doctor.py              — `nexvul doctor` self-check

  core/
    __init__.py
    discovery.py           — file discovery, gitignore, limits
    language.py            — language detection
    limits.py              — per-file resource limits
    cache.py               — content-hash cache
    errors.py              — error hierarchy

  ir/
    __init__.py
    nodes.py               — IR node types (dataclasses)
    facts.py               — semantic fact types
    edges.py               — relationship types
    builder.py             — IR construction from parsed ASTs
    visitor.py             — IR visitor/walker base class

  parser/
    __init__.py
    python/
      __init__.py
      parser.py            — ast.parse() wrapper with limits
      ir_converter.py      — Python AST -> IR
    javascript/
      __init__.py
      parser.py            — tree-sitter wrapper with limits
      ir_converter.py      — tree-sitter CST -> IR

  analysis/
    __init__.py
    symbols.py             — symbol table construction
    imports.py             — cross-file import resolution
    callgraph.py           — call graph builder
    cfg.py                 — control flow graph
    taint/
      __init__.py
      engine.py            — generic taint engine
      lattice.py           — taint lattice (Tainted/Clean/Unknown)
      specs.py             — source/sink/sanitiser/propagator types
      summaries.py         — function summary computation and application

  frameworks/
    __init__.py
    base.py                — framework recogniser base class
    registry.py            — framework recogniser registry
    langchain.py
    langgraph.py
    crewai.py
    autogen.py
    openai_agents.py
    mcp.py

  rules/
    __init__.py
    base.py                — rule base classes (TaintRule, PatternRule, etc.)
    registry.py            — rule discovery and registration
    engine.py              — rule evaluation engine
    asi06/                 — memory & context poisoning rules
    asi07/                 — insecure inter-agent communication rules
    asi08/                 — cascading failure rules
    asi09/                 — human-agent trust exploitation rules
    asi10/                 — rogue agent rules

  reporting/
    __init__.py
    base.py                — reporter base class
    terminal.py            — Rich-powered terminal output
    json_reporter.py       — JSON output
    sarif.py               — SARIF 2.1.0 output
    normaliser.py          — finding deduplication, fingerprinting, ranking

  schemas/
    finding/
      v1.json              — finding JSON schema

  config/
    defaults.py            — default configuration values
    schema.py              — .nexvul.yml schema and validation
```

### 10.1 Dependency Policy

**Runtime dependencies (minimal):**
- Python 3.12+ standard library (`ast`, `json`, `pathlib`, `typing`, etc.)
- `click` or `typer` — CLI framework
- `rich` — terminal formatting
- `pydantic` or `dataclasses` — data validation (prefer stdlib dataclasses)
- `tree-sitter` + `tree-sitter-typescript` + `tree-sitter-javascript` — JS/TS parsing
- `pyyaml` — YAML config loading (safe_load only)

**No runtime dependencies on:**
- Any ML/AI library
- Any network library (requests, httpx, etc.)
- Any database library
- Semgrep, CodeQL, Bandit, or any other scanner

**Dev dependencies:**
- `pytest`, `pytest-cov`, `pytest-timeout`
- `mypy` — type checking
- `ruff` — linting and formatting
- `pre-commit` — git hooks for nexvul's own development

**Supply-chain policy:**
- Minimise dependencies. Every dependency is an attack surface.
- Pin exact versions in lock files.
- Audit new dependencies before adding.
- Prefer stdlib over third-party when quality is comparable.
- No transitive dependency on Node.js, npm, or any JavaScript runtime.
