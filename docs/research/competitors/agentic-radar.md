# Agentic Radar (SPLX AI)

**GitHub:** https://github.com/splx-ai/agentic-radar
**Stars:** 1,100 | **Forks:** 150 | **License:** Apache-2.0
**Commits:** 103 on main | **Watchers:** 19
**Language:** Python | **Open issues:** 12 | **Open PRs:** 3

## Architecture

Takes a **system-level view** rather than individual component scanning:
- Parses entire workflow definitions (not just individual functions)
- Generates dependency graphs showing agent-to-tool-to-data relationships
- Maps findings to OWASP Top 10 LLM Applications and OWASP Agentic AI Threats

Internal architecture details are not documented in the README.

## Rule Model

Not rule-based in the traditional sense. Analyzes workflow structure:
- Tool identification and classification
- MCP server detection
- Prompt extraction and analysis
- Vulnerability mapping based on workflow patterns

## Taint Analysis

None apparent. Focus is on structural/workflow analysis rather than data flow.

## Framework Detection

| Framework | Scan | MCP Detection | Prompt Hardening | Agentic Test |
|-----------|------|--------------|-----------------|-------------|
| OpenAI Agents | Yes | Yes | Yes | Yes |
| CrewAI | Yes | Yes | Yes | No |
| n8n | Yes | Yes | No | No |
| LangGraph | Yes | Yes | No | No |
| Autogen | Yes | Yes | Yes | No |

## Output Formats

- **HTML report** (primary output) -- the standout feature
- No JSON or SARIF output mentioned
- Example report: https://agentic-radar.neocities.org

## CI Integration

Not explicitly documented. No GitHub Action. Could be run in CI with `pip install` + CLI.

## CLI UX

```bash
pip install agentic-radar
# For CrewAI: pip install "agentic-radar[crewai]"

# Scan and generate report
agentic-radar scan langgraph -i path/to/folder -o report.html
agentic-radar scan crewai -i path/to/folder -o report.html
agentic-radar scan openai-agents -i path/to/folder -o report.html

# Runtime adversarial testing (OpenAI Agents only)
agentic-radar test openai-agents path/to/entrypoint.py
# Requires OPENAI_API_KEY

# Prompt hardening
agentic-radar scan crewai -i path/ -o report.html --harden-prompts
# Requires OPENAI_API_KEY
```

## Dashboard/Visual

**Best HTML report in this competitive set.** The report includes:
- Workflow visualization with dependency graphs
- Tool inventory
- MCP server listing
- Vulnerability mapping with OWASP categories
- Hardened prompt suggestions (when enabled)
- Test results table (agent name, test type, input, output, pass/fail, explanation)

Screenshots in README:
- `docs/overview_image.png` -- main overview
- `docs/prompt_hardening.png` -- hardened prompts
- `docs/test_results.png` -- test results table

## Unique Features

1. **Prompt hardening** -- rewrites detected system prompts to be more secure (LLM-powered).
2. **Runtime adversarial testing** -- sends prompt injection, PII leakage, harmful content, and fake news attacks against running agents.
3. **n8n support** -- unique in this set; scans no-code/low-code workflows.

## What They Do Well

1. **HTML report with workflow visualization** -- the best visual output of any tool here. Dependency graphs make agent architecture visible.
2. **System-level view** -- sees agent-to-agent, agent-to-tool relationships, not just individual functions.
3. **Framework breadth** -- 5 frameworks including n8n (unique).
4. **Prompt hardening** -- automated remediation, not just detection.
5. **Runtime testing** -- moves beyond static analysis.
6. **Strong community** -- 1.1k stars, endorsed by LangChain.
7. **Privacy-aware** -- static analysis runs locally; only optional features call LLMs.

## What They Do Poorly

1. **No traditional rule engine** -- can't suppress or customize what's checked.
2. **No SARIF or JSON output** -- only HTML. Useless for CI gates.
3. **No taint analysis** -- misses data-flow vulnerabilities entirely.
4. **Runtime testing limited to OpenAI Agents** -- other frameworks get scan only.
5. **Requires LLM API keys** for best features (prompt hardening, testing).
6. **Python version constraint** -- CrewAI extras require Python >= 3.10 and < 3.13.
7. **No pre-commit hook or GitHub Action**.
8. **Commercial upsell** -- some features may migrate to SplxAI's paid platform.

## Rule Quality

N/A -- not a rule-based scanner. Quality depends on the workflow parsing and pattern recognition, which is more structural than security-specific. No published accuracy metrics.

## Lessons for nexvul

- Copy: HTML report with dependency graph visualization. This is the gold standard for presentation.
- Copy: system-level workflow analysis (agent topology, not just individual functions).
- Copy: n8n/no-code support concept.
- Improve: add taint analysis and a rule engine underneath the workflow view.
- Improve: add SARIF/JSON output for CI integration.
- Avoid: requiring LLM API keys for core functionality.
