# nexvul — Brand

> Status: **Proposed direction** (Phase 0). Owner: Design (Dave). Date: 2026-10-08.
> Colour values live in [`tokens.json`](tokens.json); this file explains the choices. Nothing here is final until
> the product owner signs off `open-decisions.md` OD-10.

## 1. Positioning in one line

**Static checks for risky patterns in AI-agent code and MCP configs. Runs locally.**

What the brand must make people feel: *this tool is careful, and it tells me what it did not check.* Every
other security scanner competes on "finds more". nexvul competes on "you can believe what it says" (brief §0).
The brand therefore borrows from instrument design — calibrated, labelled, honest about range — and avoids the
visual language of protection (shields, locks, padlocks, green ticks, "armour").

## 2. Name usage

- Always lowercase: **nexvul**, including in headings. Avoid starting a sentence with it; rephrase ("Run
  nexvul…", "With nexvul, …").
- Never "NexVul", "NEXVUL", "Nexvul", "nexvul.ai", "nexvul AI".
- Rule IDs are uppercase: `NEX001`. The CLI is `nexvul`. Config is `.nexvul.yml`.
- The name contains "vul". Copy must still never call a finding a vulnerability (`design-system.md` §8.1);
  taglines such as "find vulnerabilities in your agents" are out.

## 3. Wordmark

- Set in the **monospace system stack** at weight 700 with −0.02em tracking (kept from the report mock-up).
  *Why mono:* nexvul lives in terminals and code review; the wordmark should look like something you type.
- No custom font file. The wordmark renders identically from the token font stack everywhere it appears,
  including the offline HTML report, which may not load fonts (CSP).
- Minimum size 12px; clear space = the height of the `x` on all sides.

## 4. Mark — the trace

The existing mock-up uses a shield in a blue-violet gradient tile. **Proposed replacement (DV-7):** a *trace* —
three nodes joined by a path, the last node open — the shape of the thing nexvul actually shows you:
source → flow → sink.

```
   ●───●───○
```

Reference SVG (24×24, inline, single colour, `currentColor` so it themes automatically and needs no external
asset under the report's CSP):

```svg
<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2"
     stroke-linecap="round" aria-hidden="true">
  <circle cx="4" cy="12" r="2.5" fill="currentColor"/>
  <circle cx="12" cy="12" r="2.5" fill="currentColor"/>
  <circle cx="20" cy="12" r="2.5"/>
  <path d="M6.5 12h3M14.5 12h3"/>
</svg>
```

*Why not a shield:* a shield says "protected". nexvul cannot protect anything; it reads code. A mark that makes
a promise the product cannot keep undermines the one thing the product sells.

*Why the open last node:* the sink is where the risk lands, and the open circle reads as "this is where you
look". It also works at 16px as a favicon without detail loss.

Tile treatment for avatars (GitHub org, PyPI, Marketplace): mark in `#e2e4ea` on `#13161f`, 20% padding, 8px
radius. No gradient (the mock-up's accent→violet gradient is dropped: gradients do not survive monochrome
printing or 1-bit Marketplace badges).

## 5. Palette

| Role | Value | Use |
|---|---|---|
| Ink (dark surfaces) | `#0c0e14`, `#13161f`, `#191d29` | Backgrounds of report, social cards, avatar tile |
| Paper (light) | `#f5f6f8`, `#ffffff` | Docs, print |
| Signal blue (accent) | `#6c8aff` fill / `#8aa4ff` text on dark / `#3654dc` text on light | Rule IDs, links, the mark on light surfaces |
| Severity set | see `tokens.json` → `severity` | **Only** for severity. Never decorative, never in marketing graphics as "brand colours" |
| Partial yellow + hatch | `#f0c541` | Only for incomplete scans |

There is deliberately **no brand green**. Marketing graphics, social cards and the README never show a green
tick, a "0 vulnerabilities" badge, or a "passing" style badge for scan results.

## 6. Voice (summary; full rules in `design-system.md` §8)

| We are | We are not |
|---|---|
| Precise: names the API, the file, the line | Alarming: "critical threat detected!" |
| Candid about limits: says what was not checked | Reassuring: "you're all set", "secure" |
| Calm and brief | Clever, jokey, or full of emoji |
| On the developer's side: "Add an approval step before…" | Scolding: "insecure code", "you forgot" |
| Specific about evidence: "Confidence: medium (cross-file flow)" | Vague: "may be risky" with no reason |

**README and release-note headlines** follow the same rules. Good: *"nexvul 0.2: TypeScript flows for
LangChain.js, and partial-scan reporting in SARIF."* Not: *"nexvul 0.2 makes your agents bulletproof."*

## 7. README hero (D01) composition

```
[trace mark] nexvul

Static checks for risky patterns in AI-agent code and MCP configs.

[PyPI version] [licence] [CI]

    pipx install nexvul
    nexvul scan .

[screenshot: terminal T04 at 100 columns, dark theme, real sample-repo output]

A clean result does not prove your application is secure.
Runs locally. No account, no telemetry, no network.
```

- Screenshot is T04 (findings with a flow), not T02. *Why:* the flow is the differentiator; a zero-finding
  screenshot teaches readers that the goal is a clean screen.
- No OWASP logo or badge: it reads as endorsement. Text says "maps findings to the OWASP Top 10 for Agentic
  Applications (ASI06–ASI10 focus)".
- No comparison table until benchmark artefacts exist (brief §33; D08).

## 8. Assets to produce (not done in this pass)

| Asset | Size | Notes |
|---|---|---|
| Mark SVG (mono, `currentColor`) | 24 viewBox | Source above |
| Favicon for HTML report | inline `data:` SVG | No external file under CSP |
| Social card | 1280×640 | Wordmark + one-line positioning + a cropped T04 flow; no tick, no shield |
| GitHub Action / Marketplace icon | Marketplace `branding` (Feather icon + colour) | Marketplace only offers Feather icons: recommend `git-commit` (closest to the trace) and colour `blue`; never `shield` |
| Terminal screenshots | 100 cols, both themes | Generated from the real CLI once it exists; never mocked for the README |
