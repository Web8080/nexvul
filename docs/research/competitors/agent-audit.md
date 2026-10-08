# Agent Audit

**GitHub:** https://github.com/HeadyZhang/agent-audit
**Stars:** 237 | **Forks:** 28 | **License:** MIT
**Commits:** 168 on master | **Open issues:** 3 | **Open PRs:** 3
**Language:** Python

## Architecture

Pipeline runs on .py, .json, .yaml, .env files:

1. **PythonScanner** -- AST analysis with two components:
   - `TaintTracker`: source-to-sink reachability
   - `DangerousOperationAnalyzer`: tool boundary detection
2. **SecretScanner** -- regex candidates then `SemanticAnalyzer` with 3-stage filtering (known formats, entropy/placeholder checks, context)
3. **MCPConfigScanner** -- server provenance, path permissions, auth gaps
4. **PrivilegeScanner** -- daemon, sudoers, sandbox, credential store checks
5. All feed a **RuleEngine** that produces findings

## Rule Model

- Rule IDs: `AGENT-NNN` (e.g., AGENT-001 for command injection, AGENT-031 for MCP env exposure)
- Grouped by OWASP category ASI-01 through ASI-10
- Each rule has CWE mapping and remediation guidance in `docs/RULES.md`
- **Count discrepancy:** About section says 51, README body says 66. Likely updated between versions.

## Taint Analysis

- Tracks data from `@tool` function parameters to sinks (`eval`, `subprocess.run`, `cursor.execute`)
- **Intra-procedural only** -- no cross-function or cross-module tracking
- Sanitization detection (recognizes when data is properly escaped)
- Only triggers when a confirmed tool entry point has unsanitized params reaching a dangerous op

## Framework Detection

Deep support:
- LangChain, CrewAI, AutoGen, AgentScope
- Generic `@tool` rules for other frameworks
- Also targets OpenAI Agents SDK and raw function calling

## Output Formats

- Terminal (default)
- JSON
- SARIF
- Markdown

## CI Integration

- GitHub Action: `HeadyZhang/agent-audit@v1`
- Also available as OpenClaw skill
- `--save-baseline` / `--baseline --fail-on-new` for incremental scanning

## CLI UX

```
agent-audit scan <path>
agent-audit inspect stdio -- <command>   # read-only MCP server inspection
--format json|sarif
--output <file>
--severity <level>
--fail-on <level>
--save-baseline <file>
--baseline <file> --fail-on-new
```

## Dashboard/Visual

None. Terminal text report with severity badges. No HTML report. No screenshots in README.

## Benchmark Results (v0.20.0)

- **F1 (raw): 0.7581** on 81-sample / 238-label ground truth (v2.2)
- Precision: 68.86%, Recall: 84.32%
- TP: 199, FP: 90, FN: 37
- Comparison on same subset: Bandit F1 0.46, Semgrep F1 0.43
- Both Bandit and Semgrep score 0% recall on MCP configuration checks
- Test suite: 1,873 passed, 1 failed by design, 4 skipped
- Known limitation: benchmark is partly self-labeled, GT refresh planned

**Note:** Earlier README versions claimed F1 of 0.909 on 22-sample benchmark. The larger benchmark lowered it. The adjusted F1 of 0.84 is computable but not used as headline.

## Known Issues

- TS AST path is silently disabled due to stale `tree_sitter_typescript` language-module API bug (issue filed Jul 2026). TypeScript analysis may not work.

## What They Do Well

1. **Benchmark transparency** -- publishes F1, precision, recall with reproducible methodology and comparison to Bandit/Semgrep.
2. **Semantic secret detection** -- 3-stage filtering reduces false positives vs. regex-only.
3. **MCP config scanner** -- dedicated parser for mcp.json, claude_desktop_config.json.
4. **Baseline/incremental scanning** -- `--save-baseline` and `--fail-on-new` enables adoption in existing codebases.
5. **Live MCP inspection** -- `agent-audit inspect stdio` connects to running MCP servers read-only.
6. **Large test suite** (1,873 tests).

## What They Do Poorly

1. **TS/JS AST is broken** -- silently disabled, major gap.
2. **Intra-procedural taint only** -- same limitation as competitors.
3. **68.86% precision** -- roughly 1 in 3 findings is a false positive.
4. **No HTML report** -- only terminal/JSON/SARIF/markdown.
5. **No pre-commit hook**.
6. **Self-labeled benchmark** -- credibility gap until independent validation.

## Rule Quality

Rules are Python-code-defined with AST analysis. The taint tracker with sanitization detection shows real sophistication. The 3-stage secret filtering is more advanced than simple regex. However, the TS path being broken undermines the multi-language claim.

## Lessons for nexvul

- Copy: benchmark methodology with F1/precision/recall, baseline scanning, MCP server inspection.
- Copy: semantic secret detection approach (regex -> entropy -> context).
- Improve: actually working TS/JS parsing, cross-file taint, HTML reports.
- Avoid: self-labeled benchmarks without external validation.
