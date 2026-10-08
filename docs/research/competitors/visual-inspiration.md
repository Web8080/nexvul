# Visual Inspiration: How Security Tools Present Themselves

## HTML Report Best Practices

### Agentic Radar (Best in Class for Agent Scanners)
- Self-contained HTML file generated with `-o report.html`
- Contains workflow dependency graphs showing agent-to-tool relationships
- OWASP vulnerability mapping with severity indicators
- Hardened prompt suggestions inline
- Test results table (agent, test type, input, output, pass/fail, explanation)
- Example: https://agentic-radar.neocities.org

### Trivy (Best in Class for Container/Dependency Scanning)
- Built-in HTML template: `trivy image --format template --template "@contrib/html.tpl" -o report.html`
- Summary by severity (Critical, High, Medium, Low) with expandable sections
- Each section shows CVEs, affected packages, file paths
- Covers vulnerabilities, misconfigurations, and secrets in one report
- Template renders from internal data structures -- extensible

### Multi-Engine Scanner Pattern
- Normalizes outputs from multiple scan engines into a common data model
- Highlights dual-verified findings (confirmed by 2+ engines)
- Shows severity, plain-language description, affected component, remediation step per row
- Key insight: **information hierarchy over completeness** -- don't show every field

### Design Principles for nexvul's HTML Report

1. **Self-contained** -- single HTML file, no CDN dependencies, works offline
2. **Secrets redacted** -- show file, line, rule, never the matched value
3. **Information hierarchy** -- summary dashboard first, drill-down to details
4. **Dark/light mode** -- respect `prefers-color-scheme`
5. **Exportable** -- PDF-friendly layout for stakeholder sharing
6. **OWASP category grouping** -- organize findings by ASI01-10 with category descriptions
7. **Workflow graph** -- SVG dependency graph of agent topology (like Agentic Radar)
8. **Severity distribution chart** -- bar or donut chart of findings by severity
9. **Trend tracking** -- if baseline exists, show new vs. existing findings
10. **Rule documentation inline** -- each finding links to its rule description and remediation

## README Presentation Patterns

### Badge Row (Standard Pattern)

Most successful security tools use a badge row at the top:

```markdown
[![PyPI version](https://badge.fury.io/py/nexvul.svg)](...)
[![License](https://img.shields.io/github/license/org/nexvul)](...)
[![Python](https://img.shields.io/pypi/pyversions/nexvul)](...)
[![Tests](https://github.com/org/nexvul/actions/workflows/test.yml/badge.svg)](...)
[![OpenSSF](https://www.bestpractices.dev/projects/NNNNN/badge)](...)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-blue)](...)
```

### What Top Tools Include

**Trivy (20k+ stars)**
- Hero banner/logo
- Badge row (version, Go report, license, GitHub Actions)
- One-line description
- Feature matrix table
- Quick start with copy-paste commands
- GIF/screenshot of terminal output
- Architecture diagram
- Comparison table vs. competitors

**Semgrep (10k+ stars)**
- Clean logo
- "Find bugs and enforce code standards" tagline
- Quick install + run example
- Language support grid
- Link to playground
- Enterprise features section

**Grype (8k+ stars)**
- ASCII art logo
- Badge row
- One-liner description
- Installation options (Homebrew, curl, Docker)
- Usage example with output
- Comparison with other tools

**Snyk CLI**
- Professional branding
- Badge row (npm version, license, downloads)
- Quick start
- Feature list with icons
- Link to docs

### What Works (Common to All)

1. **Hero visual** -- logo, banner, or terminal screenshot above the fold
2. **One-line value prop** -- what it does in 10 words or fewer
3. **Install in one command** -- `pip install nexvul` or `brew install nexvul`
4. **Run in one command** -- `nexvul scan .`
5. **Output screenshot** -- real terminal output or HTML report preview
6. **Feature comparison table** -- vs. existing tools (Semgrep, Bandit, etc.)
7. **OWASP/CWE badge** -- shows security credibility
8. **CI snippet** -- GitHub Actions YAML, copy-paste ready
9. **Exit codes documented** -- CI gating depends on this
10. **"What this does NOT do"** -- scope limitations build trust

### What Doesn't Work

1. **Wall of text** -- lose readers before the install command
2. **No screenshots** -- users can't visualize what they'll get
3. **ASCII art only** -- looks dated, not professional
4. **Feature claims without evidence** -- "57 rules" without linking to rule docs
5. **No comparison** -- users need to know why this over Semgrep/Bandit

## Terminal Output Inspiration

### Effective Patterns
- **Severity colors** -- Critical=red, High=orange, Medium=yellow, Low=blue
- **Finding counter** -- "Found 12 issues (3 critical, 5 high, 4 medium)"
- **File:line format** -- clickable in terminals that support it
- **Rule ID + one-line description** -- `ASI01-001: LLM output passed to subprocess without sanitization`
- **Remediation hint** -- one sentence on how to fix
- **Summary table** -- category breakdown at the end
- **Exit code documentation** -- 0=clean, 1=findings, 2=error

### Anti-Patterns
- Dumping raw JSON to stdout by default
- No color (everything looks the same)
- No summary (user has to count findings manually)
- Verbose stack traces in normal operation
