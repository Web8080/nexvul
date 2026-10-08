# CodeQL — Research Notes for nexvul

> Last updated: 2026-10-08. Sources: GitHub docs, CodeQL standard libraries,
> GitHub Security Lab licence page, RIOT-OS community assessment.

## Database / QL Model

CodeQL works in two phases:

### 1. Database Creation

CodeQL extracts a **relational database** from source code. The database
contains a complete representation of the codebase:

- AST nodes and their relationships
- Type information (from compiler/interpreter)
- Control flow graphs
- Name binding and symbol resolution
- File and location information

For interpreted languages (Python, JS), CodeQL runs its own extractor that
parses and resolves symbols. For compiled languages (C/C++, Java), it
intercepts the build process to capture the compiler's view.

The database is a set of relational tables stored on disk. Queries run
against this snapshot — the database is immutable after creation.

### 2. QL Query Language

QL is a declarative, object-oriented query language (Datalog-inspired):

```ql
from DataFlow::Node source, DataFlow::Node sink
where myConfig.hasFlowPath(source, sink)
select sink, source, sink, "Tainted data reaches $@.", sink, "sink"
```

Key concepts:
- **Classes** model AST node types, with inheritance
- **Predicates** define reusable logic (like functions)
- **Recursion** is supported (Datalog-style fixed-point)
- **Aggregates** (`count`, `max`, `min`, `sum`) for metrics

## Sources / Sinks / Sanitizers / Flow Steps

CodeQL's taint tracking uses a **configuration class** pattern:

- `isSource(DataFlow::Node node)` — defines where tainted data originates
- `isSink(DataFlow::Node node)` — defines dangerous destinations
- `isSanitizer(DataFlow::Node node)` / `isBarrier(...)` — where taint is
  removed (renamed from "sanitizer" to "barrier" in recent versions)
- `isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b)` — custom
  propagation steps beyond the default model

### Data Extensions (Models-as-Data)

CodeQL supports **data extensions** — external YAML/CSV files that declare
sources, sinks, and summaries without writing QL:

- **Source models:** Mark API return values as tainted
- **Sink models:** Mark API parameters as dangerous
- **Summary models:** Describe how data flows through library functions
  (input → output mappings, taint vs. value preservation)
- **Neutral models:** Explicitly mark functions as "not relevant" to
  suppress false positives

Summaries handle code not present in the repository (third-party libraries).
Models can be packaged as **CodeQL model packs** for reuse.

### Flow Analysis

CodeQL's data-flow analysis is:
- **Inter-procedural:** tracks across function calls
- **Context-sensitive:** distinguishes call sites
- **Field-sensitive:** tracks through object attributes
- **Cross-file:** follows imports/exports
- **Type-aware:** leverages extracted type information

This is significantly more powerful than Semgrep OSS but requires the
database creation step and the QL query language.

## Licence Constraints

**This is critical for nexvul's architecture decisions.**

CodeQL's licence (GitHub CodeQL Terms of Use) restricts usage:

| Use Case | Permitted? |
|---|---|
| Academic research | Yes |
| Open-source projects (OSI-approved licence) | Yes |
| Generating databases for CI/CD on GitHub.com-hosted OSS | Yes |
| CI/CD on private/proprietary code | **Requires GitHub Advanced Security licence** |
| Embedding CodeQL in another tool | **No (without separate agreement)** |
| Redistributing CodeQL binaries | **No** |
| Using CodeQL CLI offline on proprietary code | **No (without GHAS)** |

The CLI and Action wrappers are MIT-licensed, but the CodeQL engine itself
is proprietary (gratis for qualifying open-source use).

**Consequence for nexvul:** nexvul cannot embed, bundle, or depend on CodeQL.
CodeQL is a reference architecture, not a dependency.

## What to Borrow for nexvul

### Borrow (Concepts Only)

1. **Database-as-snapshot model.** Parse once, query many times. nexvul's
   IR should be a queryable in-memory model that rules interrogate without
   re-parsing.

2. **Configuration class pattern.** Defining sources/sinks/sanitizers as
   data that plugs into a generic taint engine is elegant and extensible.
   nexvul should adopt this: rules declare their source/sink/sanitizer
   predicates, the taint engine does the work.

3. **Summary models for libraries.** nexvul needs framework-specific
   summaries (e.g., "LangChain's `AgentExecutor.invoke()` passes tool
   results to the LLM") that describe data flow through framework code
   without analysing the framework source.

4. **Separation of extraction and analysis.** CodeQL's clean split between
   database creation (language-specific) and querying (language-neutral QL)
   maps to nexvul's parser → IR → rule engine pipeline.

5. **Context sensitivity.** CodeQL tracks which call site a data-flow path
   goes through. nexvul should aim for at least call-site sensitivity in
   its function summaries.

### Cannot Borrow (Implementation)

- The QL language itself (proprietary, not embeddable)
- The CodeQL CLI or libraries (licence restrictions)
- The extractor binaries (proprietary)

nexvul's taint engine must be built from scratch, informed by CodeQL's
design but implemented independently in Python.
