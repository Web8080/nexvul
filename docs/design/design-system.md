# nexvul — Design System

> Status: **Proposed design** (Phase 0). Owner: Design (Dave). Date: 2026-10-08.
> Machine-readable values: [`tokens.json`](tokens.json) — the terminal reporter, the HTML report template, the
> SARIF writer and the copy lint all read from it. **No colour, glyph, severity number or fixed sentence is
> hard-coded anywhere else.**

## 1. Principles

1. **Scope before verdict.** Every surface says what was analysed before, or alongside, what was found. There is
   no "pass" state in nexvul's visual language — only *complete* or *not complete*, and *findings* or *none*.
2. **Evidence over adjectives.** A finding is a source, a path, a sink and a reason. Words like "dangerous" are
   replaced by the specific API and the specific missing control.
3. **Colour is the third cue, never the first.** Every meaning is carried by a word first, a shape second
   (meter, pattern, position) and colour third. Output must be complete with colour off.
4. **Untrusted text looks untrusted.** Repo-derived text is always shown in a code style (monospace, inset) and
   never styled as nexvul's own voice — never bold, never a heading, never a link.
5. **Quiet when it is fine, loud when it is incomplete.** The loudest visual element in the whole system is the
   partial-scan banner, not the critical finding. *Why:* a critical finding is already actionable; an
   incomplete scan is the one result people misread.

## 2. Colour

Values and contrast ratios: `tokens.json` → `color.dark`, `color.light`. Every text token is ≥ 4.5:1 on its
card surface (WCAG 2.2 AA, normal text); checked with the formula in `_build/` notes, recorded per token.

| Role | Dark | Light | Rule |
|---|---|---|---|
| Page / card | `#0c0e14` / `#191d29` | `#f5f6f8` / `#ffffff` | Kept from the existing report mock-up |
| Text default / muted / dim | `#e2e4ea` / `#8890a4` / `#80889d` | `#1a1d27` / `#5b6270` / `#636a77` | **dim changed** (was `#555d74`, 2.57:1 on card — fails AA) |
| Accent (rule IDs, links to nexvul docs) | `#8aa4ff` | `#3654dc` | Only for nexvul-authored interactive or ID text |
| Critical / High / Medium / Low / Info | `#ff6b85` / `#ff9d57` / `#f0c541` / `#6cb6ff` / `#a3abbf` | `#c41d3a` / `#a64c08` / `#8a6100` / `#1f5fb8` / `#5b6474` | See §3 |
| Partial banner | fill `#f0c541`, ink `#14161c`, 45° hatch | same | 10.99:1 |
| Failed banner | fill `#c41d3a`, ink `#ffffff` | same | 5.86:1 |
| Complete status | default ink | default ink | **No green anywhere in the system** |

**Why no green.** The mock-up used `--clean: #3dd68c` for zero-finding tiles and "ok" completeness values.
Green is the universal "safe" signal; a zero-finding tile in green says "secure" no matter what the footer says.
Complete status uses neutral ink; `ok` rows in `doctor` use the word `ok`, not a colour.

## 3. Severity encoding (colour-blind safe)

Severity is carried by **three independent cues**, each sufficient on its own:

| Severity | Word | Meter (Unicode / ASCII) | Hue (dark) | Terminal SGR (16-colour) |
|---|---|---|---|---|
| critical | `CRITICAL` | `████` / `[####]` | rose `#ff6b85` | bold bright-white on red `1;97;41` |
| high | `HIGH` | `███░` / `[###.]` | orange `#ff9d57` | bold red `1;31` |
| medium | `MEDIUM` | `██░░` / `[##..]` | yellow `#f0c541` | yellow `33` |
| low | `LOW` | `█░░░` / `[#...]` | blue `#6cb6ff` | blue `34` |
| info | `INFO` | `░░░░` / `[....]` | grey `#a3abbf` | dim `2` |

**Reasoning**

- **Meter = ordinal shape.** Four cells filled from the left reads as a quantity in every culture and survives
  greyscale, colour-blindness, `NO_COLOR` and screen readers (which read the word, not the meter; the meter is
  `aria-hidden` in HTML).
- **Hue choices.** Red and orange are hard to separate for protanopes and deuteranopes; that is accepted because
  the word and meter already separate them. Low moves from the mock-up's **teal** (`#4ec9b0`) to **blue**:
  teal was close to the old "clean" green and to medium-yellow under tritanopia, and blue is the hue most
  reliably distinct from red/orange/yellow across the three common colour-vision deficiencies.
- **Luminance ordering (dark theme).** Critical is the only severity rendered as a **filled** badge (reverse
  video in the terminal, tinted fill + border in HTML); the rest are text-coloured. Fill vs no-fill is a fourth
  cue that does not depend on hue.
- **Terminal uses the user's palette.** 16-colour SGR codes map to the user's terminal theme, which respects
  their accessibility choices. nexvul never emits 24-bit colour in the terminal. *Why:* a fixed hex in a
  terminal ignores a user's high-contrast or colour-blind theme.

Confidence is never colour-coded. It is a word (`confidence high`), dim, after the ASI tags.

## 4. Status encoding

| Status | Terminal | HTML | Markdown (job summary) |
|---|---|---|---|
| `COMPLETE` | `Status COMPLETE` in bold default ink | Status tile, default ink | `**Scan complete.**` |
| `PARTIAL SCAN` | full-width bold black-on-yellow line, last line of output | sticky non-dismissable banner, yellow with 45° hatch, repeated in print | H2 heading starts `PARTIAL SCAN:` + blockquote |
| `SCAN FAILED` | bold white-on-red line | red banner, no tiles except Status | H2 heading starts `SCAN FAILED:` |

The hatch pattern exists so the partial banner is distinguishable from a medium-severity badge in greyscale and
for users who cannot see yellow.

## 5. Terminal rules

1. **Streams.** Results to stdout; progress, warnings and diagnostics to stderr. Machine formats on stdout are
   never interleaved with human text.
2. **Colour off** when any of: `NO_COLOR` is set to any value (no-color.org), `--no-color`, `TERM=dumb`,
   stdout is not a TTY. Forced on by `--color=always`, or `FORCE_COLOR` when `NO_COLOR` is unset. With colour
   off the output contains **zero** ESC (0x1B) bytes (SR-11 test).
3. **ASCII mode** when the output encoding is not UTF-8 or `NEXVUL_ASCII=1`: meter, rules and separators use
   `tokens.json → terminal.*_ascii`.
4. **Untrusted text** is rendered only as Rich `Text` objects after the shared sanitiser: C0/C1/ESC/DEL, bidi
   controls and Unicode category Cf are shown as visible escapes (`\x1b`, `\u{202E}`); no Rich markup parsing,
   no highlighting, no emoji substitution (T-11).
5. **Status lines are printed last and built only from trusted strings.**
6. **Width.** `COLUMNS` or the terminal size; unknown → 100. Body text wraps at `min(width-2, 100)`. Below 80,
   stacked layout (T16). Below 40, no wrapping.
7. **Links.** OSC 8 hyperlinks only for local `file://` paths nexvul constructs from the resolved scan root;
   never in CI, never from scanned content.
8. **No animation** beyond a counter redrawn at most 10 times a second on stderr; no spinners. *Why:* spinners
   in CI logs become thousands of lines.

## 6. HTML report foundations

- **Self-contained, offline, no fonts.** System font stacks only (`tokens.json → type.family`); CSP
  `default-src 'none'` with hashed inline style and script; `img-src data:` only (the mark is inline SVG).
- **Progressive enhancement.** All content is in static HTML; `<details>` for expansion; JS only for regrouping
  (H08). Report is complete with scripts blocked (H10).
- **Type scale** 11/12/14/16/20/28 px; body 14px/1.5; code 12px/1.7; counts in tabular numerals.
- **Spacing** 4px base (4, 8, 12, 16, 20, 24, 32, 40). Card padding 14×16 (kept from mock-up).
- **Motion** 150 ms ease-out on hover/expand only; 0 ms under `prefers-reduced-motion`. No entrance animations
  on load (a report that animates its counts invites screenshots of the animation, not the numbers).
- **Touch targets** ≥ 44×44 px for group/filter controls and `<summary>` rows.
- **Print** (H09): light palette forced, all details expanded, banner on page 1, disclaimer in page footer.
- **Themes:** `prefers-color-scheme` with `data-theme` override, exactly as the mock-up implements it.

## 7. Component inventory

| Component | Terminal | HTML | Markdown (GitHub) | Notes |
|---|---|---|---|---|
| Header block | `nexvul <ver>  scan of <path>` + Files / Frameworks / Rules / Config rows | header bar + meta | job summary bold status line | Always includes rules run and frameworks |
| Severity badge | `LABEL meter` | pill: word + meter (`aria-hidden`), critical filled | `████ Critical` in table cell | Word always present |
| Finding block | §T04 layout | card (H05) with `<details>` | table row linking to code scanning | Location always `path:line[:col]` |
| Flow list | numbered rows, `source`/`sink` words | ordered list with role words + marker colour | code scanning "Show paths" | Never a single `→` chain longer than one line |
| Fix line | `Fix  …` | "How to fix" section | rule help | Built-in text |
| Suppressed table | rule, location, kind, justification | collapsed `<details>` table | table, justification in code span | Justification is untrusted text |
| Weakened-config list | key: value — applied / NOT APPLIED (why) | list in H07 | "Configuration" section | Always shown when non-empty |
| Completeness block | compact (2 lines) when complete; full table otherwise | strip under tiles + full H07 | status line + reasons table | Rendered from trusted accounting |
| Partial banner | last line, reverse video | sticky banner | H2 + blockquote | §4 |
| Result line | last line before banner | Status tile + footer | H2 heading | Includes exit code |
| Hint line | `Learn a rule: nexvul explain NEX0nn` | link to rule section | text | One per screen, not per finding |
| Untrusted code span | sanitised `Text`, default ink | `<code>` via `textContent` | inline code span with adaptive fence | §5.4 of github-and-action.md |
| Disclaimer | in T02, U08, `--help` | footer, every page | `<sub>` footer | Fixed string from tokens |

## 8. Tone of voice

**Voice:** a careful senior reviewer leaving a comment on your pull request. Specific, calm, short, on your
side. States what it saw, what it could not see, and what to do.

**Rules**

1. Second person, active voice, present tense. "Tool `refund_order` calls `stripe.Refund.create()`…" not
   "A potentially dangerous call was detected".
2. Name the API, the function, the file. Never "this code", "something", "an issue".
3. Say what nexvul did not see whenever absence is the finding ("No approval step was found … in the scanned
   code").
4. Errors say what happened, then what to do. No apology, no blame, no exclamation marks, no emoji.
5. Severity words appear only as labels, never as adjectives in prose ("this is a critical problem" → no).
6. Never speak for the attacker's success. "Could allow", "can carry instructions" — not "allows attackers to
   take over".
7. Numbers are exact or absent. No "many", no "several" where a count exists.

### 8.1 Banned phrases (enforced by copy lint over every nexvul-authored string, rule docs and README)

| Banned | Why | Write instead |
|---|---|---|
| secure / security passed / is secure | nexvul cannot establish security | "No findings from enabled rules." + disclaimer (only the fixed disclaimer may contain "secure", negated) |
| safe / safe to deploy / safe to merge | same | "No findings at or above `high`." |
| no vulnerabilities / vulnerability-free / clean bill of health (affirmative) | same; findings are patterns, not vulnerabilities | "0 findings"; the partial banner's negated "not a clean bill of health" is the only permitted use |
| clean / all clear / looks good / passed / ✅ / ✓ | reads as a verdict | "Scan complete", "0 findings" |
| vulnerable / vulnerability (for a finding) | implies proven exploitability | "finding", "risky pattern" |
| detected an attack / rogue agent detected / malicious code found | nexvul observes code shape, not intent | "missing containment", the specific capability |
| protected / hardened / guaranteed / verified (of the user's code) | unprovable | the specific control found or not found |
| OWASP compliant / covers the OWASP Agentic Top 10 / OWASP-certified | no compliance semantics exist; partial coverage | "maps findings to ASI06–ASI10" |
| 100% / complete coverage / full coverage / percentages of OWASP covered | implies completion semantics | counts of rules per ASI category |
| dangerous / scary / critical issue (as prose) | adjective without evidence | the source, sink and missing control |
| just / simply / obviously | blames the reader | delete |
| sorry / oops / whoops | apology tone for a tool | state the cause |
| AI-powered / smart detection | false (v1 has no LLM) and irrelevant | "static analysis" |

**Allowed exceptions** (exact strings from `tokens.json → copy`): the disclaimer, the no-findings sentences and
the partial banner. The lint allowlists those strings verbatim, not the words.

### 8.2 Message formulas

| Message type | Formula | Example |
|---|---|---|
| flow finding | `{source} reaches {sink} {where} without an identified {control}.` | "Content returned by requests.get() reaches vector_store.add_documents() without an identified validation or trust-boundary check." |
| control-absence finding | `{actor} {action}. No {control} was found on the path to the call in the scanned code.` | NEX018 example |
| config finding | `{object} {is configured with} {literal}.` | "graph.compile() is invoked with recursion_limit=None." |
| capability finding | `Agent {name} can {cap 1} and {cap 2}; no {limit} was found.` | "Agent research_agent can run shell commands and send HTTP requests to any host; no approval step or iteration limit was found." |
| fix | imperative, one sentence, names the control | "Set a finite recursion_limit sized to the longest legitimate run." |
| error | `{what failed}: {specific cause}. {what to do}. {what did not happen}` | "Config error in .nexvul.yml:7:3 … Nothing was scanned." |

## 9. Accessibility checklist (per surface)

- Text contrast ≥ 4.5:1 for every text token on its surface (tokens record ratios).
- Severity, status and flow roles never colour-only (§3, §4, flow role words).
- HTML: landmark regions (`header`, `main`, `footer`); banner `role="alert"` on load for partial/failed;
  `<details>/<summary>` for disclosure (keyboard and screen-reader native); meter glyphs `aria-hidden="true"`;
  focus outline 2px accent, never removed.
- Terminal: output readable by screen readers in plain mode (no box art required to understand structure;
  headings are words on their own line).
- Reduced motion respected.

## 10. Deviations from `assets/report-preview.html` (need product-owner sign-off)

| # | Mock-up | This design | Reason |
|---|---|---|---|
| DV-1 | Completeness section at the bottom | One-line strip under tiles + full section; banner at top for partial | Scope before verdict (§1); threat model §7 rule 5 requires a top banner |
| DV-2 | `--clean` green for zero/ok values | Removed; neutral ink | §2 "Why no green" |
| DV-3 | "OWASP Coverage ASI06–10 · 5 categories scanned" tile | Removed; rules-run count in the completeness strip | Implies full category coverage; compliance-style claim nexvul cannot evidence |
| DV-4 | Low severity teal `#4ec9b0` | Blue `#6cb6ff` | Colour-blind separation; teal read as "clean" |
| DV-5 | `--fg-dim #555d74` | `#80889d` | 2.57:1 fails WCAG AA |
| DV-6 | Severity as coloured text pill only | Word + meter; critical filled | Not colour-only (§3) |
| DV-7 | Shield logo mark | Trace mark (see `brand.md`) | A shield claims protection |
| DV-8 | Rule IDs NEX001/NEX002/NEX003/NEX011/NEX012/NEX013/NEX021/NEX022/NEX031/NEX032/NEX033/NEX041 with titles that do not match the taxonomy | IDs and titles from `docs/detection-taxonomy.md` | IDs are a public contract; the mock-up predates the taxonomy |
| DV-9 | Copy such as "This capability combination allows autonomous destructive actions", "Any network client can invoke its tools", "(default is unbounded in LangGraph <0.2)" | Formulas in §8.2 | Overclaims certainty; the LangGraph default is an unverified version claim (brief §33) |
| DV-10 | Dataflow as one horizontal `→` chain | Numbered vertical steps with role words and locations | Long chains overflow; each step needs a location to be disputable |
| DV-11 | Footer disclaimer in italic 11px dim | Disclaimer at body size in T02/H02; footer remains | The disclaimer is the product's core claim, not small print |
| DV-12 | No suppressed section, no weakened-config list, no provenance (commit, rules hash, config source) | H06, H07 | Visible suppressions (G8) and auditability (G9) |
