# Handoff: Competitive Intelligence Research

**Date:** 2026-10-08
**Author:** Research Agent
**Status:** Complete

## Summary

Researched 6 competing AI agent security scanners. Individual profiles written to `docs/research/competitors/`. Comparison matrix and strategic positioning in `docs/research/competitors/README.md`. Visual inspiration in `docs/research/competitors/visual-inspiration.md`.

## Key Findings

### Market State
- The space is young. The most-starred tool (Snyk Agent-Scan, 3.1k stars) launched mid-2025. Most tools have <250 stars.
- No tool combines code-level taint analysis with workflow topology visualization and an HTML report.
- JS/TS support is universally weak -- broken, heuristic, or delegated to Semgrep.
- Cross-file taint analysis does not exist in any tool.
- Only one tool (Agentic Radar) produces an HTML report. Everyone else is terminal/JSON/SARIF.

### Tool Archetypes
1. **Code analyzers** (agentic-top10-scan, Agent Audit, agentic-semgrep-rules): Parse Python AST, find taint flows, map to OWASP. Weak on JS/TS and visualization.
2. **Workflow analyzers** (Agentic Radar): Parse agent topology, generate dependency graphs, produce HTML reports. No taint analysis.
3. **Runtime inspectors** (Snyk Agent-Scan, Cisco MCP Scanner): Connect to running MCP servers, analyze tool descriptions. No source code analysis.

### nexvul's Unique Position
nexvul can be the first tool to combine all three archetypes: code-level taint analysis + workflow topology + runtime-aware MCP inspection, with an HTML report and fully local execution.

## Files Written

| File | Content |
|------|---------|
| `docs/research/competitors/agentic-top10-scan.md` | Profile: 57 rules, Python AST, OWASP ASI01-10 |
| `docs/research/competitors/agent-audit.md` | Profile: AST taint, F1 0.758, broken TS |
| `docs/research/competitors/agentic-semgrep-rules.md` | Profile: 36 Semgrep rules, precision-first |
| `docs/research/competitors/agentic-radar.md` | Profile: workflow viz, HTML report, 1.1k stars |
| `docs/research/competitors/snyk-agent-scan.md` | Profile: runtime MCP scan, 3.1k stars, API-dependent |
| `docs/research/competitors/cisco-mcp-scanner.md` | Profile: YARA + LLM engines, package scanning |
| `docs/research/competitors/README.md` | Comparison matrix + strategic positioning |
| `docs/research/competitors/visual-inspiration.md` | HTML report and README presentation patterns |

## Next Steps

1. Use the priority stack in README.md to sequence feature development.
2. Build a benchmark dataset (public, independently labeled) before writing rules.
3. Design the HTML report template early -- it is the primary differentiator for adoption.
4. Set up tree-sitter for JS/TS parsing to avoid the broken-parser trap.
