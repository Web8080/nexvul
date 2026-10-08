# Cisco MCP Scanner

**GitHub:** https://github.com/cisco-ai-defense/mcp-scanner
**Stars:** 1,100 | **Forks:** 138 | **License:** Apache-2.0
**Commits:** 142 on main | **Watchers:** 12
**Language:** Python | **Package:** `cisco-ai-mcp-scanner` (PyPI)

## Architecture

Three scanning engines that can run together or independently:

1. **YARA engine** -- pattern-based rule matching against tool descriptions, schemas, prompts
2. **LLM-as-judge engine** -- sends tool definitions to an LLM for semantic analysis
3. **Cisco AI Defense API** -- cloud-based analysis via Cisco's inspect API

Connects to MCP servers via the MCP protocol to discover tools, then runs analyzers against tool descriptions and schemas.

## Rule Model

- **YARA rules** for pattern matching (prompt injection keywords, credential harvesting patterns, code execution indicators)
- Custom YARA rules can be added
- LLM analysis uses configurable prompts
- No traditional rule IDs or OWASP mapping mentioned

## Taint Analysis

None. Analyzes tool descriptions and schemas, not source code data flow.

## Framework Detection

Not framework-specific. Scans any MCP server regardless of the framework used to build it. Supports:
- Remote servers (SSE, streamable HTTP)
- stdio servers
- Config-file-based discovery
- Well-known client config locations

## Output Formats

- `summary` -- concise overview
- `detailed` -- full findings breakdown
- `table` -- tabular view
- `by_severity` -- grouped by severity
- `raw` -- raw JSON

## CI Integration

- `static` subcommand for scanning pre-generated JSON offline (CI/CD use)
- REST API server mode (`mcp-scanner-api`) for integration
- No GitHub Action

## CLI UX

```bash
# Scan remote MCP server
mcp-scanner remote --server-url <url> --analyzers yara --format summary

# Scan stdio server
mcp-scanner stdio --command "python server.py" --analyzers yara,llm

# Scan from config file
mcp-scanner config --config-file mcp.json

# Scan well-known locations
mcp-scanner known-configs

# Additional scan types
mcp-scanner prompts --server-url <url>
mcp-scanner resources --server-url <url>
mcp-scanner instructions --server-url <url>
mcp-scanner behavioral --path /path/to/code    # LLM-assisted source review
mcp-scanner pypi-scan <package>                 # Docker-sandboxed
mcp-scanner npm-scan <package>                  # Docker-sandboxed
mcp-scanner supplychain --path /path/to/code
mcp-scanner vulnerable-package --path /path     # pip-audit wrapper
mcp-scanner virustotal --path /path             # hash lookup
```

## Dashboard/Visual

- Animated GIF demo in README
- Text-based table and detailed output examples
- No HTML report

## Unique Features

1. **Package scanning** -- `pypi-scan` and `npm-scan` download and analyze packages in Docker sandbox
2. **VirusTotal integration** -- hash-based file scanning
3. **Supply chain scanning** -- behavioral analysis of MCP server source code
4. **REST API mode** -- can run as a service
5. **Behavioral code analysis** -- LLM-assisted source code review

## What They Do Well

1. **Multi-engine approach** -- YARA + LLM + cloud API gives layered detection.
2. **Broadest scan surface** -- tools, prompts, resources, instructions, packages, supply chain, VirusTotal.
3. **Package scanning in Docker** -- sandboxed analysis of PyPI/npm packages is unique.
4. **REST API mode** -- enables platform integration.
5. **YARA extensibility** -- users can add custom YARA rules.
6. **Multiple output formats** -- 5 formats including raw JSON.
7. **Cisco backing** -- resources and documentation site.

## What They Do Poorly

1. **MCP-only scope** -- doesn't scan agent application code (Python/JS/TS).
2. **YARA is noisy** -- independent audit found it flags "You MUST call this tool" whether adversarial or intentional. High false positive rate.
3. **LLM dependency** -- best detection requires LLM API keys and external calls.
4. **No SARIF output** -- can't integrate with GitHub code scanning.
5. **No OWASP mapping** -- findings lack standardized categorization.
6. **No taint analysis** -- analyzes descriptions, not code data flow.
7. **No GitHub Action or pre-commit hook**.
8. **Executes MCP servers** -- same risk as Snyk agent-scan.
9. **No HTML report** despite rich data.

## Rule Quality

YARA rules are pattern-based -- effective for known attack patterns but prone to false positives on legitimate instructions. LLM-as-judge adds semantic understanding but is non-deterministic and requires credentials. The combination is pragmatic but not rigorous.

## Lessons for nexvul

- Copy: multi-engine concept (deterministic rules + semantic analysis).
- Copy: package scanning idea (PyPI/npm supply chain for MCP servers).
- Copy: REST API mode for platform integration.
- Improve: add OWASP mapping, SARIF output, HTML reports.
- Improve: add actual source code analysis (taint tracking in Python/JS/TS).
- Avoid: high false positive rates from overly broad YARA patterns.
- Avoid: requiring LLM API keys for core functionality.
