# Competitive Landscape: AI Agent Security Scanners

## Comparison Matrix

| Feature | agentic-top10-scan | Agent Audit | agentic-semgrep-rules | Agentic Radar | Snyk Agent-Scan | Cisco MCP Scanner |
|---------|-------------------|-------------|----------------------|---------------|-----------------|-------------------|
| **Stars** | ~0 | 237 | ~0 | 1,100 | 3,100 | 1,100 |
| **License** | MIT | MIT | MIT | Apache-2.0 | Apache-2.0 | Apache-2.0 |
| **Rule count** | 57 | 51-66 | 36 | N/A (structural) | N/A (API-based) | YARA (extensible) |
| **Python AST** | Yes | Yes | Via Semgrep | No | No | No |
| **JS/TS AST** | Heuristics only | Broken (disabled) | Via Semgrep | No | No | No |
| **Taint analysis** | Intra-procedural | Intra-procedural | Semgrep taint mode | None | None | None |
| **Cross-file taint** | No | No | No | No | No | No |
| **MCP config parsing** | Yes | Yes | No | Yes (detection) | Yes (runtime) | Yes (runtime) |
| **MCP runtime inspection** | No | Yes (read-only) | No | No | Yes (executes) | Yes (executes) |
| **Workflow/topology** | No | No | No | Yes | No | No |
| **Framework count** | 8+ | 4-5 | 7+ (via patterns) | 5 | 14+ (discovery) | Any MCP server |
| **OWASP mapping** | ASI01-10 (2026) | ASI01-10 (2026) | LLM Top 10 (2025) | LLM Top 10 + Agentic AI | None explicit | None |
| **SARIF output** | Yes | Yes | Yes (via Semgrep) | No | No | No |
| **JSON output** | Yes | Yes | Yes | No | Yes | Yes (raw) |
| **HTML report** | No | No | No | **Yes** | No | No |
| **GitHub Action** | Yes | Yes | Yes | No | No | No |
| **Pre-commit** | No | No | **Yes** | No | No | No |
| **Benchmark/metrics** | None | F1 0.758 | None | None | None | None |
| **Runs fully local** | Yes | Yes | Yes | Partially (LLM optional) | No (API required) | Partially (YARA local) |
| **Skill scanning** | No | No | No | No | **Yes** | No |
| **Package scanning** | No | No | No | No | No | **Yes** (PyPI/npm) |
| **Prompt hardening** | No | No | No | **Yes** | No | No |
| **Runtime testing** | No | No | No | **Yes** (OpenAI only) | No | No |
| **Secret detection** | Basic | 3-stage semantic | Basic patterns | No | Yes | No |

## Key Gaps Across All Tools

1. **No tool has cross-file taint analysis.** Every taint tracker is intra-procedural at best.
2. **JS/TS support is broken or heuristic everywhere.** No tool has working, robust JS/TS AST analysis.
3. **Only Agentic Radar has an HTML report.** Everyone else is terminal/JSON/SARIF only.
4. **No tool combines code analysis with workflow topology.** You get one or the other.
5. **No tool scans A2A (Agent-to-Agent) protocol interactions** beyond basic config checks.
6. **No tool handles multi-agent orchestration patterns** (e.g., supervisor-worker, hierarchical agents).
7. **Benchmark culture is weak.** Only Agent Audit publishes F1/precision/recall, and it's self-labeled.

## Strategic Positioning for nexvul

### What to Copy

| From | Feature | Why |
|------|---------|-----|
| Agentic Radar | HTML report with workflow visualization | Best-in-class presentation. Users share these with stakeholders. |
| Agent Audit | Benchmark methodology (F1, precision, recall) | Credibility. Publish accuracy metrics from day one. |
| Agent Audit | Baseline/incremental scanning | Essential for adoption in existing codebases. |
| agentic-semgrep-rules | Pre-commit hook | Only tool that has one. Shift-left integration. |
| agentic-semgrep-rules | Precision-first design with test fixtures | Every rule should have true positive and true negative tests. |
| agentic-top10-scan | Agent manifest concept | Declaring expected agent topology enables structural checks. |
| agentic-top10-scan | Fencing awareness | Reduces false positives on deliberately sandboxed content. |
| Snyk Agent-Scan | Broad agent platform discovery | Auto-detect Claude, Cursor, Windsurf, etc. |
| Snyk Agent-Scan | Skill scanning | Unique capability, no competitor matches it locally. |
| Cisco MCP Scanner | Multi-engine approach | Deterministic rules + semantic layer. |
| Cisco MCP Scanner | Package scanning (supply chain) | PyPI/npm analysis for MCP server dependencies. |

### What to Avoid

| Trap | Who Falls Into It | Why Avoid |
|------|-------------------|-----------|
| Requiring external API for analysis | Snyk, Cisco (LLM mode) | Security tools should run fully local by default. |
| Executing untrusted MCP servers | Snyk, Cisco | Scanning should not require running the code being scanned. |
| Self-labeled benchmarks | Agent Audit | Get independent validation or use a public benchmark. |
| JS/TS as an afterthought | agentic-top10-scan (heuristics), Agent Audit (broken) | If you claim JS/TS support, it must actually work. |
| No CI integration | Agentic Radar, Snyk, Cisco | GitHub Action + SARIF is table stakes. |
| No visual output | Everyone except Agentic Radar | An HTML report differentiates and enables stakeholder sharing. |

### Where nexvul's Gap Is (Unique Positioning)

nexvul can own the intersection that no one occupies:

1. **Code analysis + workflow topology + HTML report in one tool.**
   - Agentic Radar has topology + HTML but no code analysis.
   - Agent Audit / agentic-top10-scan have code analysis but no topology or HTML.
   - nexvul should do both.

2. **Working JS/TS AST analysis.**
   - Every competitor either has heuristics, a broken parser, or delegates to Semgrep.
   - Use tree-sitter for robust multi-language AST parsing.

3. **Cross-file taint analysis.**
   - No competitor does this. Even intra-procedural is rare.
   - This is the hardest to build but the most defensible moat.

4. **Fully local, zero-dependency on LLMs or external APIs.**
   - Snyk and Cisco require external services.
   - nexvul should run air-gapped by default.

5. **A2A and multi-agent orchestration scanning.**
   - No tool scans Agent-to-Agent protocol interactions or multi-agent patterns.
   - As A2A adoption grows, this becomes a unique capability.

6. **Supply chain for agent dependencies.**
   - Cisco has package scanning but not integrated with code analysis.
   - nexvul can trace from `pip install` through to runtime tool exposure.

### Priority Stack (Build Order)

1. Python AST taint analysis with OWASP ASI01-10 mapping (match Agent Audit)
2. JS/TS AST via tree-sitter (beat everyone)
3. MCP config parsing (match agentic-top10-scan, Agent Audit)
4. SARIF + JSON + HTML report (beat everyone on output)
5. GitHub Action + pre-commit (match best of breed)
6. Workflow topology visualization (match Agentic Radar)
7. Agent platform auto-discovery (match Snyk)
8. Cross-file taint analysis (unique differentiator)
9. A2A protocol scanning (unique differentiator)
10. Supply chain scanning (match/beat Cisco)
