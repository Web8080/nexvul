# SARIF 2.1.0 — Research Notes for nexvul

> Last updated: 2026-10-08. Sources: OASIS SARIF 2.1.0 spec, GitHub docs
> (code-security/reference/code-scanning/sarif-files/sarif-support,
> upload-sarif-file).

## SARIF 2.1.0 Essentials

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for representing static analysis results as structured JSON.

### Top-Level Structure

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { ... } },
      "results": [ ... ]
    }
  ]
}
```

### Required Fields (GitHub Code Scanning)

GitHub processes SARIF 2.1.0 files. The following fields are **required**
(empty strings are NOT accepted):

**sarifLog level:**
- `$schema` — must reference the SARIF 2.1.0 schema
- `version` — must be `"2.1.0"`
- `runs[]` — at least one run

**run level:**
- `tool.driver` — tool component object
- `results[]` — array of result objects

**toolComponent (driver):**
- `name` — tool name (e.g., `"nexvul"`)
- `rules[]` — array of reporting descriptors

**reportingDescriptor (rule):**
- `id` — stable rule identifier (e.g., `"NEX001"`)
- `shortDescription.text` — one-line summary
- `fullDescription.text` — detailed description
- `help.text` — plain-text help (rendered in GitHub UI)

**result:**
- `message.text` — finding description
- `locations[]` — at least one location
- `partialFingerprints` — fingerprint object (see below)

**location / physicalLocation:**
- `artifactLocation.uri` — relative file path
- `region.startLine` — 1-based line number
- `region.startColumn` — 1-based column
- `region.endLine` — end line
- `region.endColumn` — end column

## `partialFingerprints`

GitHub uses `partialFingerprints` to deduplicate alerts across runs.

- The key GitHub uses is `primaryLocationLineHash`
- Example value: `"39fa2ee980eb94b0:1"`
- If omitted, `upload-sarif` action can compute it (requires source code
  in the checkout). The API endpoint (`/code-scanning/sarifs`) does NOT
  compute fingerprints — results may duplicate.

**nexvul strategy:** Compute `primaryLocationLineHash` ourselves. Hash the
normalised content around the finding location (e.g., 3 lines of context
with whitespace stripped). This ensures stable fingerprints even when
uploaded via the API.

## `security-severity`

The `properties.security-severity` field on a `reportingDescriptor` is a
**string** representing a float from 0.0 to 10.0:

```json
{
  "id": "NEX001",
  "properties": {
    "security-severity": "8.5",
    "tags": ["security"]
  }
}
```

**GitHub severity mapping:**

| security-severity | GitHub Level |
|---|---|
| > 9.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |
| 0.0 or invalid | No security severity |

**Important:** The `security` tag in `properties.tags` activates
security-severity handling. Without it, GitHub uses `defaultConfiguration.level`
(error/warning/note) instead.

## `help.markdown`

Optional but **strongly recommended.** GitHub renders `help.markdown` in the
alert detail view if present, falling back to `help.text`.

```json
{
  "id": "NEX001",
  "help": {
    "text": "Plain text help for tools that don't render markdown",
    "markdown": "## Untrusted data reaches persistent memory\n\n**Why this matters:** ..."
  }
}
```

nexvul should always populate both `help.text` and `help.markdown` for
every rule.

## Tags

GitHub recognises these tag values in `properties.tags[]`:

- `security` — activates security-severity; groups under Security tab
- Other documented examples: `maintainability`, `reliability`,
  `correctness`, `language-features`

**Limits:** 20 tags per rule (10 displayed in UI).

nexvul should tag all rules with `security` plus the OWASP category
(e.g., `external/owasp/asi06`).

## Upload Limits

| Limit | Value |
|---|---|
| Max compressed SARIF file size | 10 MB (gzip) |
| Runs per file | 20 |
| Results per run | 25,000 (top 5,000 shown by severity) |
| Rules per run | 25,000 |
| Tool extensions per run | 100 |
| Thread flow locations per result | 10,000 (top 1,000 shown) |
| Locations per result | 1,000 (100 shown) |
| Tags per rule | 20 (10 shown) |
| Total alerts | 1,000,000 |

## `upload-sarif` Action

Part of `github/codeql-action`. Usage:

```yaml
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
    category: nexvul          # labels results for multi-tool repos
```

### Required Permissions

```yaml
permissions:
  security-events: write    # required
  actions: read              # private repos only
  contents: read             # to compute fingerprints
```

### `category` Parameter

- Labels a set of results so multiple tools can analyse the same commit
- Without category, a later upload replaces the earlier one
- Two uploads with the same tool + category in one workflow **fail**
- Alternative: set unique `runAutomationDetails.id` in each SARIF file

### Event Triggers

Works on `push`, `pull_request`, and `schedule` events.

## nexvul SARIF Implementation Notes

1. **Always compute `partialFingerprints.primaryLocationLineHash`** to avoid
   duplicates when using the API endpoint.
2. **Set `runAutomationDetails.id`** to `"nexvul/{category}/{sha}"` for
   stable run identification.
3. **Include `codeFlows`** for taint findings — GitHub renders these as
   step-by-step paths in the alert view.
4. **Set `invocations[].workingDirectory.uri`** so GitHub resolves relative
   paths correctly.
5. **Gzip compress** output when writing SARIF for CI upload.
6. **Test against GitHub's limits** with synthetic large outputs.
7. **Injection prevention:** SARIF is JSON. Ensure all string values are
   properly escaped. Never include raw ANSI escape codes, executable
   content, or unescaped markdown that could inject into GitHub's UI.
