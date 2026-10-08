# Handoff: Visual design pass and dashboard app shell

- **From:** Design (Dave, UI/UX)
- **To:** Principal Supervisor; cc reporting implementers (HTML report), Documentation, QA/Test
- **Date:** 2026-10-08
- **Status:** Design complete for v1 visuals. Binding inputs: DEC-0007 (open decisions accepted), DEC-0009 (no accounts; local app shell).
- **Gallery:** `docs/design/design-pack.html` · file list `docs/design/design-pack.md`

## 1. What was delivered

| Deliverable | Location |
|---|---|
| Dashboard app shell mock-up (self-contained, CSP-hashed, no network, no inline handlers or style attributes) | `assets/report-preview.html` |
| Dashboard screenshots, light theme unless named (hero, full, findings expanded, filter-empty, agent map, rules, suppressions, history partial, settings, help, overview partial, dark, phone, phone menu) | `assets/screenshots/dashboard-*.png` |
| Journey storyboards J1–J6: swim lanes, grey-box screens, actions, decisions, failure paths with copy | `docs/design/wireframes/*.html` (+ `.png` previews) |
| Rendered screens: T02, T04, T05, T09, U01, U03, U05, U06, T15 at 80 and 120 cols; K02; G01/G05, G02/G03, A05, A01, A03 | `docs/design/screens/*.png` + `.html` sources |
| New screen IDs H14–H24 (app shell, narrow menu, findings view, filter-empty, agent map, rules, suppressions, history, settings, help, display prefs) | `docs/design/screen-inventory.md` §5 |
| Tokens: white light page, `nav`, `border.strong`, `app.*` (hatch, shadow, scrim, mock band, graph strokes), `layout.app_shell`, `storage` | `docs/design/tokens.json` |
| Deviations DV-13 (white default), DV-14 (app shell) | `docs/design/design-system.md` §10 |
| DEC-0009 pointer | top of `docs/design/open-decisions.md` |
| Generators (re-render everything; each checks tag balance, token-only colours, no handlers, no network) | `docs/design/_build/{common,dashboard_data,dashboard,wireframes,screens,pack}.py` |

## 2. How the dashboard works (for the implementer)

- **View switching is progressive enhancement.** All eight views are static HTML in one file. Without JS they render one after another and the menu links are in-page anchors (H10 holds). The hashed script adds `html.js`, shows one view from `location.hash` (`#overview`, `#findings`, `#findings/F3`, `#findings/sev=high`, `#findings/rule=NEX015`, `#agents`, `#rules`, `#suppressions`, `#history`, `#settings`, `#help`), and wires filters, the narrow menu, theme and copy buttons with `addEventListener`.
- **CSP:** `default-src 'none'; style-src 'sha256-…'; script-src 'sha256-…'; img-src data:`. No `style=` attributes anywhere (a hash does not cover them). Charts are inline SVG.
- **Escaping:** every repo-derived string is HTML-escaped and control/bidi characters are shown as `U+202E` tokens. The sample includes the hostile filename `tools/<img src=x onerror=alert(1)>.py` (finding F9) and a U+202E justification and path; the generator asserts they are escaped.
- **Preferences:** `localStorage["nexvul.report.prefs"]` (theme, density, show low/info, wrap code), every access in try/catch; blocked storage shows a message and keeps prefs for the tab only.
- **Design-only controls, not product:** the top band's *Preview state* (Complete/Partial) and the `?theme=` / `?scan=` / `?nav=open` query parameters used for screenshots. Remove both in the real report.
- **Sample data** extends terminal T04 (5 findings) to 9 findings and 22 of 25 rules run, so every view has content. Terminal and GitHub screens keep the original 5-finding sample.

## 3. Not done or not verified

- No account, sign-in, sign-up, log-out or password screens: out of scope by DEC-0009. A hosted dashboard needs its own decision and threat model.
- Screenshots come from headless Chrome on macOS only. Firefox, Safari and Windows fonts are not checked. Screen-reader pass not done; keyboard paths reviewed in code only.
- Phone captures use a 390 px iframe harness because headless Chrome enforces a 500 px minimum window.
- Deep links that scroll to a card (`#findings/F3`) leave a blank band in headless captures; it works in a normal browser, but that was not checked by hand.
- Print stylesheet (H09) is minimal: it hides the chrome and shows every view. Not rendered to PDF.
- GitHub screens are schematic. Real code-scanning rendering of `suppressions[]` and tool notifications is still unverified (contract ask CA-3).
- "Added on this branch" for local runs needs the scanner to diff suppressions against the base ref. **Contract ask for the architect:** expose `suppressions[].introduced_in_change: bool|null` and `scan.base_ref` in JSON (affects H20, A01).
- Framework version ranges and "rules attached" counts in H18 need engine output (`frameworks[].version_hint`, `frameworks[].evidence`, `rules_attached`). **Contract ask** (affects H18).
- Per-phase timings (H21) need `scan.phases[]` with durations. **Contract ask.**
