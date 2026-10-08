# agentic-top10-scan

**GitHub:** https://github.com/Adyanullah-Khan/agentic-top10-scan
**Stars:** ~0 | **Forks:** ~0 | **License:** MIT
**Last release:** v0.1.0 (Oct 2026) | **Commits:** 2 on main
**Language:** Python | **Dependencies:** PyYAML, tomli (< 3.11)

## Architecture

- **Python parsing:** Full AST via `ast` module. Intra-procedural taint tracking from sources (request data, LLM output, tool arguments, secrets) through assignments, f-strings, method calls, import aliases, and same-module helper returns to sinks (prompts, shell, SQL, eval, file paths, HTTP, memory writes).
- **JavaScript/TypeScript:** Line-based heuristics only. No JS parser bundled.
- **Fencing awareness:** Content inside explicit delimiters (e.g., `<untrusted_document>`) is treated as fenced and not flagged.
- **Test code:** Skipped by default unless `--include-tests`.
- **Privacy:** Fully local, no LLM calls, no source upload. Optional `--online` OSV lookup.

## Rule Model

- **57 rules** with IDs like `ATS-ASI05-01`, mapped to all 10 OWASP Agentic categories (ASI01-ASI10).
- Rules documented in `docs/rules.md`.
- **Suppression:** Inline comment `# agentic-top10: ignore[RULE-ID]` or `.agentic-top10.yml` config file for path exclusions, rule disabling, severity overrides.
- **Manifest:** Optional `agent-manifest.yaml` declares agents, tools, memory, oversight -- enables 7 extra checks.

## Taint Analysis

- Intra-procedural only (within function boundaries).
- Tracks sources through assignments, f-strings, method calls.
- No cross-file or cross-function tracking.

## Framework Detection

Recognizes tool decorators/registrations for:
- LangChain (`@tool`, `Tool(...)`, `BaseTool._run`)
- CrewAI (`@tool`, `BaseTool`)
- OpenAI Agents SDK (`@function_tool`)
- MCP (`@mcp.tool()`)
- pydantic-ai (`@agent.tool`)
- Semantic Kernel (`@kernel_function`)
- AutoGen (`register_for_llm`)
- Generic `tools=[...]` lists

## Output Formats

- Human-readable terminal report
- SARIF (GitHub code scanning)
- JSON
- Inline annotations
- Job summary table

## CI Integration

- GitHub Action with inputs: `path`, `fail-on`, `min-severity`, `exclude`, `disable`, `config`, `include-tests`, `online`, `sarif-file`, `upload-sarif`, `annotations`.
- Pre-commit: not mentioned.

## CLI UX

```
agentic-top10 .              # scan current directory
agentic-top10 rules          # list rules
agentic-top10 coverage       # show category coverage
--format {sarif,json}
--fail-on <severity>
--include-tests
--exclude <pattern>
```

## Dashboard/Visual

None. No HTML report. No screenshots in README.

## What They Do Well

1. **Full OWASP ASI01-ASI10 coverage** with clear category mapping per rule.
2. **Agent manifest concept** -- declaring expected agents/tools/memory enables extra checks. Novel idea.
3. **Fencing awareness** -- understands `<untrusted_document>` delimiters, reducing false positives.
4. **Privacy-first** -- zero network calls by default.
5. **Comprehensive input types** -- scans MCP configs, A2A agent cards, CrewAI configs, container defs, dependency files.
6. **Broad framework detection** -- 8+ frameworks recognized.

## What They Do Poorly

1. **JS/TS is line-based heuristics** -- no real parsing, high false positive/negative risk.
2. **Zero community traction** -- 0 stars, 0 forks, 2 commits. Unproven.
3. **No HTML report or visual output** -- terminal only.
4. **No pre-commit hook**.
5. **Intra-procedural taint only** -- misses cross-function flows.
6. **No benchmark or accuracy claims**.

## Rule Quality

Rules appear to be Python-code-defined with AST visitors, not YAML patterns. The fencing awareness and manifest-based checks show sophistication beyond simple pattern matching. However, JS/TS rules are basic regex/line-matching.

## Lessons for nexvul

- Copy: agent manifest concept, fencing awareness, OWASP category mapping per rule.
- Improve: real JS/TS AST parsing, cross-file taint, HTML report.
