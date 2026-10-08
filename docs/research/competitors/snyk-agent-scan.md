# Snyk Agent-Scan

**GitHub:** https://github.com/snyk/agent-scan
**Stars:** 3,100 | **Forks:** 287 | **License:** Apache-2.0
**Commits:** 774 on main | **Watchers:** 12
**Language:** Python | **Package:** `snyk-agent-scan` (PyPI)
**Lineage:** Formerly mcp-scan by Invariant Labs (acquired by Snyk mid-2025)

## Architecture

- Auto-discovers agent configurations from well-known paths on the machine
- For MCP servers: starts stdio servers or connects to remote URLs to retrieve tool descriptions
- Sends redacted data to Snyk/Invariant Labs API for analysis
- Two modes: **Scan** (CLI, on-demand) and **Background** (MDM-style reporting to Snyk Evo)

**Key distinction:** This is a runtime scanner, not purely static. It actually executes MCP servers to inspect their tool descriptions.

## What It Checks

### MCP Servers
- Prompt injection in tool descriptions
- Tool poisoning (hidden instructions overriding user-visible behavior)
- Tool shadowing (new server silently replacing existing tools)
- Toxic flows

### Agent Skills
- Prompt injection
- Malware payloads
- Untrusted content fetching
- Credential handling patterns
- Hardcoded secrets

## Rule Model

Not traditional rules. Uses Invariant Labs' analysis API:
- v0.5.x: Issue codes (`E*`/`W*`) with path-keyed results
- v0.6+: Scored risk indicators with `scan_path_responses` JSON

## Taint Analysis

Not traditional taint analysis. Analyzes tool descriptions and skill content semantically, not code data flow.

## Framework/Agent Detection

Auto-discovery covers:
- Claude Desktop, Claude Code
- Cursor, Windsurf, VS Code, GitHub Copilot
- Gemini CLI, OpenClaw, Amp, Kiro
- OpenCode, Antigravity, Codex, Amazon Q

Coverage varies by OS and scope (system, user, project, extension/plugin).

## Output Formats

- Human-readable terminal (default, compact in v0.6+)
- JSON (`--json`)
- SVG report (v0.6+ demo)

## CI Integration

- `--ci` flag for CI environments
- `--dangerously-run-mcp-servers` for automated scanning
- Standalone binaries available (with SBOM, checksums, signed checksums)
- No GitHub Action (run via `uvx` or binary)

## CLI UX

```bash
# Install and run
uvx snyk-agent-scan@latest

# Scan specific config
uvx snyk-agent-scan@latest ~/.cursor/mcp.json

# Scan skills directory
uvx snyk-agent-scan@latest ~/.claude/skills

# JSON output for CI
uvx snyk-agent-scan@latest --json --ci

# Flags
--no-skills              # skip skill scanning
--ignore-risks           # bypass risk checks
--show-full-discovery    # verbose discovery output
--server-timeout N       # timeout for MCP server connections
--dangerously-run-mcp-servers  # skip consent prompts
```

## Dashboard/Visual

- v0.5.x: Pretty-printed terminal output with severity colors
- v0.6+: SVG report showing scored MCP server and skill risks
- README includes output screenshots/SVG

## What They Do Well

1. **Largest community** -- 3.1k stars, most mature project in this space.
2. **Broadest agent discovery** -- auto-detects 14+ agent platforms.
3. **Runtime MCP inspection** -- actually connects to servers and analyzes real tool descriptions.
4. **Skill scanning** -- unique capability to scan agent skill files.
5. **Corporate backing** -- Snyk resources, Invariant Labs research.
6. **Standalone binaries** -- no Python required for deployment.
7. **Consent model** -- asks before starting each MCP server.
8. **Background mode** -- continuous monitoring, not just one-shot scans.

## What They Do Poorly

1. **Requires API token** -- sends data to Snyk's servers. Not fully local.
2. **Executes MCP servers** -- security risk from running untrusted code during scanning.
3. **No source code analysis** -- doesn't parse Python/JS/TS code for taint flows.
4. **No SARIF output** -- can't integrate with GitHub code scanning.
5. **No GitHub Action** -- requires custom CI setup.
6. **Not accepting contributions** -- closed development model.
7. **Large-scale scanning restricted** -- registry scanning requires Snyk permission.
8. **v0.5 to v0.6 migration** -- breaking changes in output format.

## Rule Quality

N/A -- not rule-based. Quality depends on Invariant Labs' API analysis, which is opaque. Users can't inspect or customize the detection logic.

## Lessons for nexvul

- Copy: broad agent platform discovery, skill scanning concept.
- Copy: consent model before executing anything.
- Learn from: the distinction between static analysis and runtime inspection. Both are valuable.
- Avoid: requiring external API for core analysis. Keep it local.
- Avoid: executing untrusted code during scanning without sandboxing.
- Improve: combine Snyk's runtime MCP inspection with actual source code taint analysis.
