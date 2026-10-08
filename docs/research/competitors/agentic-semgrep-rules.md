# agentic-semgrep-rules

**GitHub:** https://github.com/basitalisandhu/agentic-semgrep-rules (canonical)
**Stars:** Low (forks exist under nawaaaaaAaar, Cid-oe) | **License:** MIT
**Language:** Semgrep YAML rules | **Requires:** Semgrep >= 1.179

## Architecture

Not a standalone scanner -- a Semgrep rule pack. Users install Semgrep and point it at the YAML config. Semgrep does the parsing and matching.

- **Python:** 23 rules leveraging Semgrep's AST-aware pattern matching
- **TypeScript/JavaScript:** 13 rules
- **Semgrep handles the AST** -- rules use `pattern`, `pattern-either`, `metavariable-regex`, `taint` mode

## Rule Model

- 36 rules total in a single YAML file (`agentic-semgrep-rules.yaml`) or split into `rules/` directory
- Each rule has: ID, CWE mapping, OWASP LLM Top 10 (2025) mapping, fix-oriented message
- Every rule has a test fixture (true positive marked with `ruleid:`, negative with `ok:`)
- **Precision is stated design goal** -- reports zero findings on author's own 21-file codebase

### Rule Categories

| Category | Rules |
|----------|-------|
| LLM output to code execution | `llm-output-to-exec-eval`, `llm-output-to-os-system`, `llm-output-to-subprocess`, `llm-output-to-child-process`, `llm-output-to-eval-function` |
| LLM output to injection sinks | `llm-output-to-sql`, `llm-output-to-fetch`, `llm-output-to-http-request`, `llm-output-to-file-path`, `llm-output-to-html`, `llm-output-to-innerhtml` |
| Prompt injection | `user-input-in-system-prompt` (Python + JS/TS) |
| Over-broad tools | `agent-tool-param-to-shell`, `agent-tool-param-to-file-path`, `mcp-tool-param-to-shell`, `mcp-tool-param-to-file-path`, `langchain-allow-dangerous-*` |
| Exposed MCP servers | `fastmcp-http-transport-without-auth`, `mcp-http-transport-without-auth`, `fastmcp-bind-all-interfaces` |
| Secrets | `hardcoded-llm-api-key`, `llm-api-key-logged`, `api-key-in-command-line-arg` |
| Unsafe loading | `pickle-load-model-file`, `torch-load-without-weights-only`, `transformers-trust-remote-code`, `yaml-unsafe-load`, `langchain-allow-dangerous-deserialization` |

### Source Recognition

Tracks "model output" from: OpenAI, Anthropic, LiteLLM, Ollama, Google GenAI, Vercel AI SDK, LangChain/LangGraph.

Tool parameters treated as attacker-influenced from: FastMCP, MCP SDKs, LangChain, OpenAI Agents, pydantic-ai, Semantic Kernel, Vercel AI.

## Taint Analysis

Leverages Semgrep's built-in taint mode for source-to-sink tracking. This is more capable than custom AST walkers -- Semgrep can track across assignments and some function boundaries (intra-file).

## Framework Detection

Not framework detection per se -- rules match specific decorator/API patterns from multiple frameworks.

## Output Formats

- Console (Semgrep default)
- SARIF (via `--sarif`)
- JSON (via `--json`)

## CI Integration

- GitHub Action: `basitalisandhu/agentic-semgrep-rules@v1` with inputs for severity, SARIF upload, config
- pre-commit hook: `agentic-semgrep-rules` hook ID
- Registry publication: `p/agentic-semgrep-rules` (listed as pending)

## CLI UX

```bash
pip install semgrep
semgrep --config https://raw.githubusercontent.com/.../agentic-semgrep-rules.yaml .
# or
semgrep --config agentic-semgrep-rules/rules .
# CI:
semgrep --metrics=off --error --severity ERROR --config ...
```

## Dashboard/Visual

None. Uses Semgrep's native output. Semgrep App (commercial) provides dashboards.

## What They Do Well

1. **Precision-first design** -- every rule tested, zero false positives on reference codebase.
2. **Leverages Semgrep's mature engine** -- AST parsing, taint mode, cross-assignment tracking for free.
3. **Multi-language from day one** -- Python AND JS/TS with real parsing (not heuristics).
4. **Pre-commit hook** -- only tool in this set with one.
5. **Specific, actionable rule names** -- `llm-output-to-subprocess` tells you exactly what.
6. **Source recognition breadth** -- covers 7+ LLM providers and 7+ tool frameworks.
7. **Low barrier** -- one pip install + one command. No custom scanner to maintain.

## What They Do Poorly

1. **Not a standalone tool** -- requires Semgrep installation and knowledge.
2. **36 rules is the smallest set** -- gaps in coverage (no MCP config parsing, no manifest, no privilege checks).
3. **No MCP config file analysis** -- only code patterns, not config files.
4. **No agent manifest or workflow analysis** -- purely function-level.
5. **No benchmark or accuracy metrics** beyond "zero findings on my code."
6. **Limited OWASP mapping** -- uses LLM Top 10 2025, not Agentic Top 10 2026.
7. **No HTML report**.

## Rule Quality

**High.** Rules use Semgrep's pattern language properly with taint mode, metavariable constraints, and pattern-either for variant coverage. Test fixtures enforce correctness. This is the most linguistically rigorous approach in the competitive set because it leverages a proven engine.

## Lessons for nexvul

- Copy: pre-commit hook, precision-first design with test fixtures per rule.
- Consider: bundling Semgrep rules alongside custom analysis (hybrid approach).
- Improve: add MCP config analysis, agent workflow analysis, OWASP Agentic mapping.
- Learn from: their source/sink taxonomy is a good starting point for rule design.
