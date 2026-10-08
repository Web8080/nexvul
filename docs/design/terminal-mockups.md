# nexvul — Terminal Mock-ups

> Status: **Proposed design** (Phase 0). All output below is illustrative sample data for a project that does
> not exist. nexvul has no working scanner yet; rule titles follow `docs/detection-taxonomy.md`.
> Owner: Design (Dave). Date: 2026-10-08. Screen IDs: [`screen-inventory.md`](screen-inventory.md).

## How to read this file

- Each block is drawn at real width. A block marked `cols:80` never exceeds 80 characters per line; `cols:120`
  never exceeds 120; `cols:60` is the narrow layout. Widths are checked by `docs/design/_build/check_widths.py`.
- Colour is described in the annotation under each block, not drawn. Every block must remain fully
  understandable in the plain rendering (T15) — that is the test for "not colour-only".
- `████ ███░ ██░░ █░░░ ░░░░` is the **severity meter** (critical, high, medium, low, info). In plain/ASCII mode it
  renders `[####] [###.] [##..] [#...] [....]`. The label word is always present next to it.
- Paths and identifiers shown here are from the scanned repo and therefore pass through the sanitiser (SR-10)
  in the real product. T13/H13 show what a hostile one looks like.
- Line order matters: findings first, completeness after, the **result line last**. A CI log tail or a
  scrolled terminal shows the last lines; those lines must carry the status.

## Layout grid

| Element | 80 columns | 120 columns |
|---------|-----------|-------------|
| Left gutter | 1 | 1 |
| Severity label + meter | cols 2–15 (`CRITICAL ████`) | same |
| Rule ID | col 17 | col 17 |
| Title | col 25 → wraps at 80 | col 25 → location right-aligned at 120 |
| Location | own line under title, indented to 17 | right-aligned on the title line when it fits, else own line |
| Body (message, flow, fix) | indent 4, wrap at 78 | indent 4, wrap at 100 (line length for reading, not screen width) |
| Rule separators | `─` × width (plain: `-`) | same |

*Why body text wraps at 100 even on wide terminals:* lines longer than ~100 characters are hard to read and
copy; wide terminals gain the right-aligned location column, not longer prose.

---

## T04 — Complete, findings at/above threshold

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       312 of 312 analysed (Python 241, TypeScript 56, configs 15)
  Frameworks  LangGraph, MCP, OpenAI Agents SDK
  Rules       25 of 25 enabled · fail-on high · config .nexvul.yml (local)
────────────────────────────────────────────────────────────────────────────────

 CRITICAL ████  NEX018  Financial action without human oversight
                ASI02 · ASI09 · confidence medium
                agent/billing.py:58:9

    Tool refund_order calls stripe.Refund.create() with an amount chosen by
    the model. No approval step was found on the path to the call in the
    scanned code.

    Flow
      1 source  agent/billing.py:31  @function_tool def refund_order(amount)
      2         agent/billing.py:44  amt = int(amount * 100)
      3 sink    agent/billing.py:58  stripe.Refund.create(amount=amt, ...)

    Fix  Require human approval before the call (needs_approval=True on the
         tool), or cap the amount in code.

 HIGH     ███░  NEX002  External content indexed into a vector store
                ASI06 · confidence high
                agent/ingest.py:42:5

    Content returned by requests.get() reaches vector_store.add_documents()
    without an identified validation or trust-boundary check.

    Flow
      1 source  agent/ingest.py:30   html = requests.get(url).text
      2         agent/ingest.py:35   text = clean(html)
      3         agent/ingest.py:38   docs = [Document(page_content=text)]
      4 sink    agent/ingest.py:42   vector_store.add_documents(docs)

    Fix  Record provenance on stored documents and validate or allowlist
         sources before indexing. Keep retrieved text out of system prompts.

 HIGH     ███░  NEX007  MCP connection without authentication or over cleartext
                ASI07 · confidence high
                mcp.json:12:7

    Server "search" is reached over http:// at a non-loopback host with no
    auth headers or OAuth configuration.

    Fix  Use https:// and configure authentication for remote MCP servers.

 MEDIUM   ██░░  NEX014  Agent iteration limit disabled or unbounded
                ASI08 · confidence high
                agent/graph.py:91:12

    graph.compile() is invoked with recursion_limit=None.

    Fix  Set a finite recursion_limit sized to the longest legitimate run.

 LOW      █░░░  NEX015  Missing timeout around agent or tool execution
                ASI08 · confidence medium
                agent/tools.py:45:16

    httpx.get() inside tool search_web has no timeout argument.

    Fix  Pass timeout= to the client or wrap the tool in asyncio.wait_for().

 Learn a rule: nexvul explain NEX018
────────────────────────────────────────────────────────────────────────────────
 Suppressed (1)
   NEX006  agent/server.py:41  inline  "auth enforced by the API gateway (i..."

 Scan completeness
   Status        COMPLETE
   Analysed      312 of 312 files · 0 skipped · 0 parse errors · 0 timeouts
   Rules run     25 of 25 enabled · cross-file analysis on
   Not analysed  3 dynamic imports (analysis-limited; see --verbose)

 Result  5 findings: 1 critical, 2 high, 1 medium, 1 low · 1 suppressed
         3 at or above fail-on (high). Exit code 1.
```

**Annotations**

1. Header: `nexvul 0.1.0` bold; labels (`Files`, `Frameworks`, `Rules`) dim; values default ink.
   *Why the header lists frameworks and rules before findings:* brief §25, and it frames every finding as
   "found by these rules in these files".
2. Severity label: CRITICAL bold on red background (16-colour `41;97`); HIGH bold red; MEDIUM yellow; LOW blue;
   INFO dim. Meter inherits the label colour. Plain mode: `CRITICAL [####]`.
3. Rule ID in accent (cyan in 16-colour); title bold. ASI tags and confidence dim. *Why confidence is a word:*
   `0.82` invites false precision; the taxonomy defines three levels.
4. Location `path:line:col` in default ink, underlined only when the terminal supports OSC 8 **and** the link
   target is a local `file://` path built by nexvul; never a URL from scanned content (T-11). Off in CI.
5. Message: one sentence, specific APIs, ends without a judgement word. NEX018 says "No approval step was
   found … in the scanned code" — control-absence findings always carry that qualifier (taxonomy §1).
6. Flow: numbered steps; `source` and `sink` are **words**, coloured magenta/yellow as a secondary cue. Code
   column truncated with `...` at the wrap width; full text in `--verbose` and the HTML report.
7. Findings without a flow (config class, e.g. NEX007, NEX014) omit the Flow block rather than printing an
   empty one.
8. The `explain` hint appears once, after the last finding, naming the highest-severity rule.
9. Suppressed block always appears when any suppression applied; justification in quotes, truncated to fit.
10. Result line is last, two lines maximum, and always contains the exit code in words. *Why the exit code:*
    developers wiring CI copy what they see.

<!-- cols:120 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       312 of 312 analysed (Python 241, TypeScript 56, configs 15)  Frameworks  LangGraph, MCP, OpenAI Agents SDK
  Rules       25 of 25 enabled · fail-on high · cross-file on              Config      .nexvul.yml (local, sha256 4be1…)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

 CRITICAL ████  NEX018  Financial action without human oversight                                   agent/billing.py:58:9
                ASI02 · ASI09 · confidence medium

    Tool refund_order calls stripe.Refund.create() with an amount chosen by the model. No approval step was found
    on the path to the call in the scanned code.

    Flow  1 source  agent/billing.py:31  @function_tool def refund_order(amount)
          2         agent/billing.py:44  amt = int(amount * 100)
          3 sink    agent/billing.py:58  stripe.Refund.create(amount=amt, currency=order.currency)

    Fix   Require human approval before the call (needs_approval=True on the tool), or cap the amount in code.

 HIGH     ███░  NEX002  External content indexed into a vector store                                agent/ingest.py:42:5
                ASI06 · confidence high

    Content returned by requests.get() reaches vector_store.add_documents() without an identified validation or
    trust-boundary check.

    Flow  1 source  agent/ingest.py:30   html = requests.get(url).text
          2         agent/ingest.py:35   text = clean(html)
          3         agent/ingest.py:38   docs = [Document(page_content=text, metadata={"url": url})]
          4 sink    agent/ingest.py:42   vector_store.add_documents(docs)

    Fix   Record provenance on stored documents and validate or allowlist sources before indexing.

 HIGH     ███░  NEX007  MCP connection without authentication or over cleartext                            mcp.json:12:7
                ASI07 · confidence high

    Server "search" is reached over http:// at a non-loopback host with no auth headers or OAuth configuration.

    Fix   Use https:// and configure authentication for remote MCP servers.

 MEDIUM   ██░░  NEX014  Agent iteration limit disabled or unbounded                                 agent/graph.py:91:12
                ASI08 · confidence high

    graph.compile() is invoked with recursion_limit=None.

    Fix   Set a finite recursion_limit sized to the longest legitimate run.

 LOW      █░░░  NEX015  Missing timeout around agent or tool execution                              agent/tools.py:45:16
                ASI08 · confidence medium

    httpx.get() inside tool search_web has no timeout argument.

    Fix   Pass timeout= to the client or wrap the tool in asyncio.wait_for().

 Learn a rule: nexvul explain NEX018
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Suppressed (1)
   NEX006  agent/server.py:41   inline   "auth enforced by the API gateway (infra/gateway.tf, route /agents/*)"

 Scan completeness   COMPLETE · 312 of 312 files analysed · 0 skipped · 0 parse errors · 0 timeouts · 25 of 25 rules
                     3 dynamic imports not analysed (see --verbose)

 Result  5 findings: 1 critical, 2 high, 1 medium, 1 low · 1 suppressed · 3 at or above fail-on (high). Exit code 1.
```

**Annotations (120 only):** location right-aligned to column 120 on the title line; when `title + location`
would collide, the location drops to its own line (80-column rule). Completeness collapses to two lines because
nothing is wrong; it expands to the full table the moment anything is (T05).

---

## T02 — Complete, no findings

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       312 of 312 analysed (Python 241, TypeScript 56, configs 15)
  Frameworks  LangGraph, MCP, OpenAI Agents SDK
  Rules       25 of 25 enabled · fail-on high · config .nexvul.yml (local)
────────────────────────────────────────────────────────────────────────────────

 No findings from enabled rules. This does not prove the application is secure.

 What was checked
   25 rules for ASI06-ASI10 patterns (and ASI02, ASI03, ASI05 secondary tags)
   312 files: every discovered file was parsed and analysed
   Cross-file flows on · 3 dynamic imports could not be followed

 What was not checked
   Runtime behaviour, deployed configuration, model behaviour, MCP servers
   configured outside this repository, and risks no enabled rule targets.
   List of rules: nexvul rules

 Scan completeness
   Status        COMPLETE
   Analysed      312 of 312 files · 0 skipped · 0 parse errors · 0 timeouts
   Suppressed    0

 Result  0 findings · scan complete. Exit code 0.
```

<!-- cols:120 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       312 of 312 analysed (Python 241, TypeScript 56, configs 15)  Frameworks  LangGraph, MCP, OpenAI Agents SDK
  Rules       25 of 25 enabled · fail-on high · cross-file on              Config      .nexvul.yml (local, sha256 4be1…)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

 No findings from enabled rules. This does not prove the application is secure.

 What was checked      25 rules (ASI06-ASI10 focus) · 312 of 312 files parsed and analysed · cross-file flows on
                       3 dynamic imports could not be followed (see --verbose)
 What was not checked  Runtime behaviour, deployed configuration, model behaviour, MCP servers configured outside this
                       repository, and risks no enabled rule targets. List of rules: nexvul rules

 Result  0 findings · scan complete · 0 suppressed. Exit code 0.
```

**Annotations**

1. The first sentence is the fixed string from SR-18, default ink, **not** green, no tick, no emoji.
   *Why:* green plus a tick is read as "secure" by everyone, regardless of the words next to it.
2. "What was not checked" is always shown on T02 and only on T02 (on screens with findings the developer
   already knows the result is not a clean bill).
3. "3 dynamic imports could not be followed" appears even on a complete scan: dynamic constructs do not make a
   scan partial (they are analysis-limited, SR-20), but hiding them would overstate the result.

---

## T03 — Complete, findings below threshold (tail only)

<!-- cols:80 -->
```text
 Scan completeness
   Status        COMPLETE
   Analysed      312 of 312 files · 0 skipped · 0 parse errors · 0 timeouts

 Result  2 findings: 1 medium, 1 low · 0 at or above fail-on (high).
         Exit code 0. Lower-severity findings are listed above.
```

*Why the second sentence:* exit 0 with findings must not look like the T02 screen in a log tail.

---

## T05 — Partial scan, with findings (tail)

<!-- cols:80 -->
```text
 ...findings as T04...
────────────────────────────────────────────────────────────────────────────────
 Scan completeness
   Status        PARTIAL
   Analysed      308 of 312 files
   Not analysed  4 files
                   parse error        2   agent/legacy.py, tools/gen_api.py
                   over size limit    1   data/fixtures.py (3.1 MB > 1 MB)
                   parser timeout     1   agent/huge_graph.py
   Limits hit    none
   Weakened      rules.disabled: NEX004 (applied; local config)

   Code in these files was not checked. Run with --verbose for details.

 Result  4 findings: 1 critical, 2 high, 1 medium · 3 at or above fail-on
         Exit code 3 (scan incomplete).
 PARTIAL SCAN — 4 of 312 files not analysed. This result is not a clean bill of
 health.
```

<!-- cols:120 -->
```text
 ...findings as T04...
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Scan completeness   PARTIAL · 308 of 312 files analysed
   Not analysed      parse error      2   agent/legacy.py, tools/gen_api.py
                     over size limit  1   data/fixtures.py (3.1 MB > 1 MB limit)
                     parser timeout   1   agent/huge_graph.py (30 s limit)
   Weakened          rules.disabled: NEX004 (applied; local config .nexvul.yml)
   Code in these files was not checked. Run with --verbose for details.

 Result  4 findings: 1 critical, 2 high, 1 medium · 3 at or above fail-on (high). Exit code 3 (scan incomplete).
 PARTIAL SCAN — 4 of 312 files not analysed. This result is not a clean bill of health.
```

**Annotations**

1. Banner: bold black on yellow background (16-colour `43;30`) across the full width, prefixed `PARTIAL SCAN —`
   so the meaning survives with colour off. Printed **after** the result line, from trusted strings only (T-11:
   untrusted text is printed before it and cannot redraw it because ESC bytes are escaped).
2. Up to 5 paths inline per reason, then `and N more`. File-count bombs cannot overflow the screen.
3. The completeness table is the full form whenever status ≠ COMPLETE.
4. Exit-code precedence: 3 beats 1 (screen-inventory §9). The result line says both facts.

---

## T06 — Partial scan, no findings

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       308 of 312 analysed (Python 238, TypeScript 55, configs 15)
  Frameworks  LangGraph, MCP
  Rules       25 of 25 enabled · fail-on high · config .nexvul.yml (local)
────────────────────────────────────────────────────────────────────────────────

 No findings in the 308 files that were analysed. 4 files were not analysed.

 Scan completeness
   Status        PARTIAL
   Analysed      308 of 312 files
   Not analysed  4 files
                   parse error        2   agent/legacy.py, tools/gen_api.py
                   over size limit    1   data/fixtures.py (3.1 MB > 1 MB)
                   parser timeout     1   agent/huge_graph.py

   Code in these files was not checked. Run with --verbose for details.

 Result  0 findings in analysed files. Exit code 3 (scan incomplete).
 PARTIAL SCAN — 4 of 312 files not analysed. This result is not a clean bill of
 health.
```

**Acceptance test:** output must not contain the T02 sentence "No findings from enabled rules".

---

## T07 — Scan failed (input cause)

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./vendor-snapshot

 SCAN FAILED — none of the 41 Python files could be parsed.

   Most likely cause: the files use Python 2 syntax. nexvul parses Python 3.12
   grammar. Run with --verbose to see the first parse error in each file.

 Result  No result. Exit code 3 (scan incomplete).
```

Annotation: `SCAN FAILED` bold white on red background; no findings section exists at all.

---

## T09 — Config error

<!-- cols:80 -->
```text
nexvul: config error in .nexvul.yml:7:3
  rules.disable: unknown key. Did you mean rules.disabled?
  Allowed keys under rules: enabled, disabled

Nothing was scanned. Exit code 2.
```

<!-- cols:80 -->
```text
nexvul: config error in .nexvul.yml:2:10
  YAML anchors and aliases are not allowed in .nexvul.yml (found &defaults).
  Write the values out in full.

Nothing was scanned. Exit code 2.
```

*Why "Nothing was scanned" every time:* a developer must never wonder whether the scan ran with half a config.

---

## T10 — Usage error

<!-- cols:80 -->
```text
nexvul: path not found: ./agnet
  Did you mean ./agent?
  Usage: nexvul scan [OPTIONS] [PATH]...   Run nexvul scan --help for options.

Nothing was scanned. Exit code 2.
```

---

## T11 — Internal error

<!-- cols:80 -->
```text
nexvul stopped unexpectedly (internal error: KeyError).
  While processing: agent/graph.py
  This is a bug in nexvul, not in your code.

  Report it: https://github.com/<owner>/nexvul/issues/new?template=bug.yml
  Include the output of: nexvul doctor  and  nexvul scan --debug
  Do not attach source code you cannot share; nexvul sends nothing anywhere.

No result was produced. Exit code 4.
```

Annotation: `<owner>` is a placeholder until the repository owner is fixed (OD-11). The URL is a constant in
nexvul, never built from scanned content.

---

## T12 — `--verbose` (additions only)

<!-- cols:120 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Effective config
    severity.fail_on        high          default
    rules.disabled          [NEX004]      .nexvul.yml:4 (local)
    exclude                 [gen/**]      .nexvul.yml:7 (local)  12 files excluded
    analysis.cross_file     true          default
    analysis.max_files      10000         default
  Plugins                   none loaded (1 entry point found and not loaded: acme-nexvul-rules 0.2 — not allowlisted)
  Timings                   discover 0.08 s · parse 1.21 s · analyse 0.94 s · report 0.05 s
  Cross-file budget         412 of 5000 path steps used
  Analysis-limited          agent/plugins.py:12 importlib.import_module(name)  name is not a constant
                            agent/plugins.py:30 getattr(module, attr)()          dynamic call target
                            tools/dyn.py:8      exec(code)                       dynamic code execution
```

---

## T13 — `--explain NEX002` inline (excerpt)

<!-- cols:80 -->
```text
 HIGH     ███░  NEX002  External content indexed into a vector store
                ASI06 · confidence high
                agent/ingest.py:42:5
    ...message and flow as T04...

    ┌ About NEX002 ─────────────────────────────────────────────────────────┐
    │ Why it matters  Documents in a vector store are retrieved later and   │
    │   placed in the model's context. Text an attacker controls on a web   │
    │   page can carry instructions that the agent follows on a future,     │
    │   unrelated request.                                                  │
    │ Not detected   Poisoned documents already in the corpus; poisoning    │
    │   via ingestion code outside this repository.                         │
    │ Full text      nexvul explain NEX002                                  │
    └───────────────────────────────────────────────────────────────────────┘
```

Plain mode replaces the box with a `About NEX002` heading and 4-space indent.

---

## T14 — `--quiet`

<!-- cols:80 -->
```text
nexvul: 5 findings (1 critical, 2 high, 1 medium, 1 low) · 1 suppressed
nexvul: scan complete · 3 at or above fail-on (high) · exit code 1
```

<!-- cols:80 -->
```text
nexvul: 0 findings in analysed files
nexvul: PARTIAL SCAN — 4 of 312 files not analysed. This result is not a clean
        bill of health. Exit code 3.
```

---

## T15 — Plain output (non-TTY, `NO_COLOR`, CI)

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       312 of 312 analysed (Python 241, TypeScript 56, configs 15)
  Frameworks  LangGraph, MCP, OpenAI Agents SDK
  Rules       25 of 25 enabled - fail-on high - config .nexvul.yml (base ref)
  Mode        CI (detected from GITHUB_ACTIONS)
--------------------------------------------------------------------------------

 CRITICAL [####]  NEX018  Financial action without human oversight
                  ASI02, ASI09 - confidence medium
                  agent/billing.py:58:9
    Tool refund_order calls stripe.Refund.create() with an amount chosen by
    the model. No approval step was found on the path to the call in the
    scanned code.
    Flow
      1 source  agent/billing.py:31  @function_tool def refund_order(amount)
      2         agent/billing.py:44  amt = int(amount * 100)
      3 sink    agent/billing.py:58  stripe.Refund.create(amount=amt, ...)
    Fix  Require human approval before the call, or cap the amount in code.

 ...

 Result  5 findings: 1 critical, 2 high, 1 medium, 1 low - 1 suppressed
         3 at or above fail-on (high). Exit code 1.
```

**Annotations**

1. Zero ESC bytes (R5). `·` replaced by `-`, `─` by `-`, meter by `[####]` when the output encoding is not
   UTF-8 or `NEXVUL_ASCII=1`; otherwise Unicode text characters are kept (they are not escapes).
2. Progress: one line per phase on stderr (`nexvul: parsing 312 files`), no carriage-return animation.
3. No blank line between message and flow: CI log viewers add their own spacing.

---

## T16 — Narrow terminal (60 columns)

<!-- cols:60 -->
```text
nexvul 0.1.0  ./my-agent-project
  312 of 312 files · 25 rules
  LangGraph, MCP, OpenAI Agents SDK
────────────────────────────────────────────────────────────

CRITICAL ████  NEX018
Financial action without human oversight
ASI02 · ASI09 · confidence medium
agent/billing.py:58:9

  Tool refund_order calls stripe.Refund.create() with an
  amount chosen by the model. No approval step was found
  on the path to the call in the scanned code.

  Flow
  1 source agent/billing.py:31
           @function_tool def refund_order(amount)
  2        agent/billing.py:44
           amt = int(amount * 100)
  3 sink   agent/billing.py:58
           stripe.Refund.create(amount=amt, ...)

  Fix  Require human approval before the call, or cap the
       amount in code.
────────────────────────────────────────────────────────────
Result  5 findings: 1 critical, 2 high, 1 medium, 1 low
        Scan complete. Exit code 1.
```

*Why stack instead of truncate:* truncating paths at narrow widths hides the one thing the developer needs to
act. Below 40 columns, nexvul stops wrapping and prints T15 layout unwrapped.

---

## T17 — Suppressions and weakened configuration (CI, full)

<!-- cols:80 -->
```text
 Suppressed (3)
   NEX006  agent/server.py:41  inline    "auth enforced by the API gateway ..."
   NEX015  agent/tools.py:88   inline    (no justification) - NOT APPLIED:
                                         CI requires a justification
   NEX002  scripts/seed.py:12  inline    "offline seed of first-party docs"
   1 suppression matched no finding: agent/old.py:12 ignore[NEX014]

 Rejected suppressions (1)
   agent/admin.py:30  ignore without a rule ID. Write ignore[NEX0nn].

 Protections weakened by repository configuration
   severity.fail_on: critical   NOT APPLIED (pull request head; CI mode)
   rules.disabled: NEX018       NOT APPLIED (pull request head; CI mode)
   Effective settings come from .nexvul.yml at base ref 3f2c1a9.
```

---

## T18 — Nothing to analyse

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./docs

 SCAN FAILED — nothing to analyse in ./docs.

   Found 14 files: 11 .md, 2 .png, 1 .json (not a recognised agent config).
   nexvul analyses Python, JavaScript, TypeScript and agent configuration
   files (MCP configs, agent manifests).

   Did you mean to scan the project root? Try: nexvul scan .

 Result  No result. Exit code 3 (scan incomplete).
```

---

## T19 — No framework recognised (header and completeness excerpt)

<!-- cols:80 -->
```text
nexvul 0.1.0  scan of ./my-agent-project
  Files       88 of 88 analysed (Python 88)
  Frameworks  none recognised
  Rules       25 of 25 enabled · fail-on high
...
 Scan completeness
   Status        COMPLETE
   Analysed      88 of 88 files
   Note          No supported agent framework was recognised. 18 of 25 rules
                 depend on one and had nothing to check. Supported: LangChain,
                 LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP.
```

---

## T20 — Interrupted

<!-- cols:80 -->
```text
^C
nexvul: scan interrupted. No result was produced. Exit code 130.
```

---

## T21 — Machine format written (stderr line)

<!-- cols:80 -->
```text
nexvul: wrote results.sarif (SARIF 2.1.0, 5 results)
nexvul: scan complete · 3 at or above fail-on (high) · exit code 1
```

<!-- cols:80 -->
```text
nexvul: wrote results.sarif (SARIF 2.1.0, 4 results)
nexvul: PARTIAL SCAN — 4 of 312 files not analysed · exit code 3
```

---

## T22 — Output refused

<!-- cols:80 -->
```text
nexvul: refusing to overwrite README.md: it is not a nexvul report.
  Use --force to overwrite it.

Nothing was scanned. Exit code 2.
```

<!-- cols:80 -->
```text
nexvul: refusing to write report.html: it is a symbolic link.
  Choose an output path that is a regular file. --force does not apply.

Nothing was scanned. Exit code 2.
```

---

## T23 — CI mode header

<!-- cols:120 -->
```text
nexvul 0.1.0  scan of . (commit 9e41d0c, pull request #212 against main 3f2c1a9)
  Mode        CI (detected from GITHUB_ACTIONS) · inline suppressions need a justification · cache off
  Config      .nexvul.yml from base ref 3f2c1a9 (sha256 77ad…) · 2 changed keys in pull request not applied
  Files       312 of 312 analysed (Python 241, TypeScript 56, configs 15)
  Frameworks  LangGraph, MCP, OpenAI Agents SDK
  Rules       25 of 25 enabled · fail-on high
```

---

## U01 — `nexvul rules`

<!-- cols:120 -->
```text
ID      Title                                                         ASI             Severity  Confidence  Status
NEX001  External content written to persistent memory                 ASI06           high      high        default
NEX002  External content indexed into a vector store                  ASI06           high      high        default
NEX003  Untrusted tool output persisted into long-term context        ASI06 ASI01     high      medium      default
NEX004  User-controlled content persisted into shared agent state     ASI06 ASI03     medium    medium      experimental
NEX005  Retrieved content promoted to trusted instructions            ASI06 ASI01     high      medium      default
NEX006  A2A / agent HTTP endpoint without authentication              ASI07           high      medium      default
NEX007  MCP connection without authentication or over cleartext       ASI07 ASI04     high      high        default
...
NEX018  Financial action without human oversight                      ASI02 ASI09     critical  medium      default
...
NEX025  No execution / iteration limits on an autonomous agent        ASI10 ASI08     medium    medium      default

25 rules · 23 on by default · 2 experimental (off) · nexvul explain <ID> for details
ASI labels for NEX016-NEX025 are provisional (pending mapping decision).
```

<!-- cols:80 -->
```text
NEX001  External content written to persistent memory
        ASI06 · high · confidence high · default
NEX002  External content indexed into a vector store
        ASI06 · high · confidence high · default
NEX003  Untrusted tool output persisted into long-term context
        ASI06 ASI01 · high · confidence medium · default
...
25 rules · 23 on by default · 2 experimental (off)
nexvul explain <ID> for details
```

Annotation: the provisional-label footer is a temporary string removed when OD-02 is decided. Status values
shown here are illustrative; no rule is implemented.

---

## U03 — `nexvul explain NEX002`

<!-- cols:80 -->
```text
NEX002  External content indexed into a vector store
        ASI06 Memory & Context Poisoning · default severity high
        confidence high (same function) / medium (across files)

WHAT IT LOOKS FOR
  Text fetched from outside the application (HTTP responses, web loaders,
  email, uploaded files) that reaches a vector-store write such as
  add_documents, add_texts, upsert or from_documents, with no validation or
  trust-boundary step that nexvul recognises in between.

WHY IT MATTERS
  Documents in a vector store are retrieved later and placed in the model's
  context. Text an attacker controls on a web page can carry instructions
  that the agent follows on a future, unrelated request.

EXAMPLE (flagged)
  html = requests.get(url).text
  vector_store.add_documents([Document(page_content=html)])

EXAMPLE (not flagged)
  if urlparse(url).hostname not in ALLOWED_SOURCES:
      raise ValueError("source not allowed")
  doc = Document(page_content=html, metadata={"source": url, "trust": "web"})

HOW TO FIX
  Allowlist the sources you index. Record provenance on every stored
  document. Keep retrieved text in user or tool messages with delimiters,
  never in system instructions.

WHAT THIS RULE DOES NOT DETECT
  Poisoned documents already in the corpus. Poisoning of embeddings or the
  model. Ingestion code outside the scanned repository. Validation helpers
  nexvul does not recognise are treated as absent (possible false positive).

SUPPRESSING THIS FINDING
  # nexvul: ignore[NEX002] -- <why this source is trusted>
  In CI the justification after -- is required.

REFERENCES
  OWASP Top 10 for Agentic Applications 2026, ASI06
  docs/rules/NEX002.md
```

Annotation: section headings bold in colour mode, uppercase so they survive plain mode. Content is the same
source as `docs/rules/NEX002.md` and SARIF `help.markdown` (one text, three renderings).

---

## U04 — `explain` unknown ID

<!-- cols:80 -->
```text
nexvul: NEX060 is not a nexvul rule.
  Did you mean NEX006 (A2A / agent HTTP endpoint without authentication)?
  List all rules: nexvul rules
```

---

## U05 — `nexvul doctor` (pass)

<!-- cols:80 -->
```text
nexvul doctor

  ok    nexvul 0.1.0 (distribution "nexvul") at ~/.local/pipx/venvs/nexvul
  ok    Python 3.12.6
  ok    Python parser: stdlib ast
  ok    JavaScript/TypeScript parser: tree-sitter grammars 0.23.x
  ok    Worker sandbox starts and enforces memory and time limits
  ok    Cache: ~/.cache/nexvul (owner-only permissions)
  ok    Built-in rules: 25, integrity sha256:9c1e… matches this release
  ok    Plugins: none loaded
  info  Network: nexvul makes no network connections and sends no telemetry

All checks passed. This checks nexvul's installation, not your code.
```

## U06 — `nexvul doctor` (problems)

<!-- cols:80 -->
```text
nexvul doctor

  warn  nexvul is installed in the same environment as the current project
        (./.venv). A malicious dependency of the project could load code
        into nexvul. Install with: pipx install nexvul
  fail  JavaScript/TypeScript parser unavailable: grammar wheel missing.
        .js/.ts files will be skipped and scans will be PARTIAL.
        Reinstall: pipx reinstall nexvul
  warn  Entry point "nexvul.rules" registered by acme-tools 1.4 (not loaded).
        Plugins load only when allowlisted in your user config.
  ok    Python 3.12.6
  ...

2 warnings, 1 failure. Exit code 1.
```

---

## U07 — `nexvul version`

<!-- cols:80 -->
```text
nexvul 0.1.0 (rules 2026.10.1, sha256:9c1e4f…) Python 3.12.6
```

---

## U08 — `nexvul scan --help` (tail)

<!-- cols:80 -->
```text
Exit codes
  0  scan complete, no findings at or above --fail-on
  1  scan complete, findings at or above --fail-on
  2  usage or configuration error (nothing scanned)
  3  scan incomplete (files not analysed, limits hit, or nothing to analyse)
  4  internal error in nexvul
A clean result does not prove the application is secure.
```

---

## K02 — pre-commit, findings block the commit

<!-- cols:80 -->
```text
nexvul...................................................................Failed
- hook id: nexvul
- exit code: 1

agent/billing.py:58  CRITICAL  NEX018  Financial action without human oversight
  fix: require approval before stripe.Refund.create(), or cap the amount
agent/ingest.py:42   HIGH      NEX002  External content indexed into a vector...
  fix: allowlist sources and record provenance before indexing

Commit blocked by nexvul (fail-on: high). Details: nexvul scan agent/
Staged-file scan: cross-file flows not checked. Run nexvul scan . for a full
scan.
```

## K01 — pre-commit pass with a suppression

<!-- cols:80 -->
```text
nexvul...................................................................Passed
```

Annotation: pre-commit hides hook output on success unless `verbose: true`; the suppression note therefore
appears only in verbose mode or in CI. This is acceptable because CI lists suppressions added by the change.

---

## C01 — `.nexvul.yml` (documented example)

<!-- cols:80 -->
```yaml
# .nexvul.yml  — protect this file with CODEOWNERS.
# In CI, settings that WEAKEN the scan are read only from the base branch.

severity:
  fail_on: high            # critical | high | medium | low | never
                           # raising this weakens the gate

rules:
  enabled: [ASI06, ASI07, ASI08, ASI09, ASI10]   # rule IDs or ASI IDs
  disabled: []             # each entry weakens the scan; list a reason in
                           # the pull request that adds it

exclude:                   # repo-relative globs; excluded files are counted
  - "gen/**"               # in every report but not analysed

frameworks:
  auto_detect: true

analysis:
  cross_file: true
  max_files: 10000         # may only be lowered here; lowering below the
                           # number of files found makes the scan PARTIAL

suppressions:
  require_justification: true   # always true in CI unless set by trusted
                                # config
```

## C03 — Inline suppression forms

<!-- cols:80 -->
```python
# nexvul: ignore[NEX006] -- auth enforced by the API gateway (infra/gateway.tf)
app.post("/agents/run")(run_agent)

client = MCPClient(url)  # nexvul: ignore[NEX007] -- loopback dev server only
```

<!-- cols:80 -->
```typescript
// nexvul: ignore[NEX016,NEX017] -- tool runs only in the sandbox account
agent.addTool(deleteTempBucket);
```

## C02/C05 — Suppression and config warnings (printed above findings)

<!-- cols:80 -->
```text
nexvul: warning: agent/admin.py:30: suppression ignored: no rule ID.
          Write ignore[NEX0nn] -- <reason>.
nexvul: warning: agent/tools.py:12: suppression ignored: it contains a hidden
          character (U+202E RIGHT-TO-LEFT OVERRIDE).
nexvul: warning: agent/graph.py:7: ignore[NEX060] names no rule. Did you mean
          NEX006?
```

*Why the hidden character is named, not shown:* printing it would reproduce the attack (T-17). The sanitiser
renders it as its code point and name.
