"""Builds docs/design/design-pack.html (gallery) and docs/design/design-pack.md (file list) from what is on disk."""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (ROOT, DESIGN, MOCK_LABEL, esc, css_vars, mark_svg, check_balanced, check_colours,
                    check_no_handlers, check_no_network, TOKENS)

REL_ASSETS = "../../assets"

DASH = [
    ("report-preview.html", "H14 H15 H01-H24", "Dashboard app shell: open the live mock-up (all views, theme toggle, filters)"),
    ("screenshots/dashboard-hero.png", "H01 H14", "Overview, 1280 px, light (README / hero)"),
    ("screenshots/dashboard-full.png", "H01 H07", "Overview, full length"),
    ("screenshots/dashboard-overview-partial.png", "H03 H01", "Overview, partial scan"),
    ("screenshots/dashboard-findings-expanded.png", "H16 H05", "Findings: filters, list, expanded finding with flow"),
    ("screenshots/dashboard-findings-filtered-empty.png", "H17", "Findings: no results for these filters (not \"no findings\")"),
    ("screenshots/dashboard-agent-map.png", "H18", "Frameworks and agent map"),
    ("screenshots/dashboard-rules.png", "H19", "Rules NEX001-NEX025"),
    ("screenshots/dashboard-suppressions.png", "H20 H13", "Suppressions, incl. a hidden-character justification"),
    ("screenshots/dashboard-history-partial.png", "H21 H07", "Scan history (this run), partial variant"),
    ("screenshots/dashboard-settings.png", "H22 H24", "Settings (read-only) and display preferences"),
    ("screenshots/dashboard-help.png", "H23", "Help and docs"),
    ("screenshots/dashboard-overview-dark.png", "H11 H24", "Dark theme (alternate)"),
    ("screenshots/dashboard-mobile.png", "H12 H15", "Phone width, 390 px"),
    ("screenshots/dashboard-mobile-menu.png", "H15", "Phone width, menu open"),
]

DOCS = [
    ("user-journeys.md", "Journeys J1-J6, failure branches, coverage check"),
    ("screen-inventory.md", "All screen IDs (T, U, K, C, H, J, G, A, D) with specifications"),
    ("terminal-mockups.md", "Terminal output at 80/120 columns (source for the rendered screens)"),
    ("github-and-action.md", "SARIF mapping, rule help, Action job summaries"),
    ("design-system.md", "Principles, colour, severity and status encoding, components, tone"),
    ("tokens.json", "Machine-readable tokens: colour, type, spacing, copy"),
    ("brand.md", "Name, wordmark, trace mark, palette, voice"),
    ("open-decisions.md", "Decisions (all accepted, DEC-0007; dashboard scope DEC-0009)"),
]

CSS = r"""
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.5 var(--body)}
a{color:var(--accent-text)}
.band{background:var(--mock-band);color:var(--mock-band-text);font-size:12px;padding:6px 16px;text-align:center;border-bottom:1px solid var(--border)}
.wrap{max-width:1240px;margin:0 auto;padding:24px 24px 64px}
header{display:flex;align-items:center;gap:10px}
.wm{font-family:var(--mono);font-weight:700;font-size:18px;letter-spacing:-.02em}
h1{font-size:28px;margin:8px 0 6px}
.lede{color:var(--muted);max-width:90ch;margin:0}
nav.toc{display:flex;flex-wrap:wrap;gap:6px 16px;margin:16px 0 8px;font-size:13px}
h2{font-size:20px;margin:36px 0 4px;padding-top:12px;border-top:1px solid var(--border)}
.sub{color:var(--muted);margin:0 0 14px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.card{display:flex;flex-direction:column;border:1px solid var(--border);border-radius:10px;background:var(--card);overflow:hidden;text-decoration:none;color:var(--text)}
.card:hover{border-color:var(--accent)}
.thumb{height:180px;overflow:hidden;background:var(--inset);border-bottom:1px solid var(--border)}
.thumb img{width:100%;display:block}
.meta{padding:10px 12px}
.ids{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent-text)}
.t{display:block;font-size:13px;margin-top:2px}
.f{display:block;font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:4px;word-break:break-all}
.hero{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:16px;align-items:start}
.hero img{width:100%;border:1px solid var(--border);border-radius:10px;display:block}
.callout{border:1px solid var(--accent);background:var(--accent-tint);border-radius:10px;padding:14px 16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-top:1px solid var(--border-subtle);vertical-align:top}
thead th{background:var(--inset);font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
code{font-family:var(--mono);font-size:12px}
@media (max-width:800px){.hero{grid-template-columns:1fr}.wrap{padding:16px}}
"""


def card(href, img, ids, title, fname):
    return ('<a class="card" href="%s"><div class="thumb"><img src="%s" alt="%s" loading="lazy"></div>'
            '<div class="meta"><span class="ids">%s</span><span class="t">%s</span><span class="f">%s</span></div></a>'
            % (esc(href), esc(img), esc(title), esc(ids), esc(title), esc(fname)))


def build():
    parts = []
    # dashboard
    dcards = []
    for f, ids, t in DASH[1:]:
        p = REL_ASSETS + "/" + f
        dcards.append(card(p, p, ids, t, "assets/" + f))
    # wireframes
    wcards = []
    for h in sorted(glob.glob(os.path.join(DESIGN, "wireframes", "*.html"))):
        b = os.path.basename(h)[:-5]
        wcards.append(card("wireframes/%s.html" % b, "wireframes/%s.png" % b, b.split("-")[0],
                           b.split("-", 1)[1].replace("-", " ").capitalize() + " (storyboard)", "docs/design/wireframes/%s.html" % b))
    # screens
    scards = []
    for h in sorted(glob.glob(os.path.join(DESIGN, "screens", "*.html"))):
        b = os.path.basename(h)[:-5]
        sid = b.split("-")[0]
        label = b.split("-", 1)[1]
        cols = label.rsplit("-", 1)[-1] if label.rsplit("-", 1)[-1].isdigit() else ""
        title = (label.rsplit("-", 1)[0] if cols else label).replace("-", " ").capitalize() + (" (%s cols)" % cols if cols else "")
        scards.append(card("screens/%s.png" % b, "screens/%s.png" % b, sid, title, "docs/design/screens/%s.html" % b))
    fcards = []
    for s in sorted(glob.glob(os.path.join(DESIGN, "flows", "*.svg"))):
        b = os.path.basename(s)
        fcards.append(card("flows/" + b, "flows/" + b, b.split("-")[0], "Journey flow diagram", "docs/design/flows/" + b))
    docs = "".join('<tr><td><a href="%s"><code>%s</code></a></td><td>%s</td></tr>' % (f, f, esc(d)) for f, d in DOCS)
    css = css_vars() + CSS
    html_ = """<!doctype html>
<html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>nexvul design pack</title><style>%(css)s</style></head>
<body><div class="band"><strong>%(mock)s</strong> &middot; Everything here is a design artefact for a scanner that is not built yet.</div>
<div class="wrap">
<header>%(mark)s<span class="wm">nexvul</span></header>
<h1>Design pack</h1>
<p class="lede">The visual companion to the design documents. Screen IDs are permanent and match <a href="screen-inventory.md">screen-inventory.md</a>. Open this file from disk; it loads only local files next to it.</p>
<nav class="toc"><a href="#dash">Dashboard app shell</a><a href="#wire">Journey wireframes</a><a href="#screens">Rendered screens</a><a href="#flows">Flow diagrams</a><a href="#docs">Documents</a></nav>
<h2 id="dash">Dashboard app shell (local report, v1)</h2>
<p class="sub">White by default, dark as an alternate. No accounts, sign-in or server (DEC-0009); Settings is read-only.</p>
<div class="hero"><a href="%(ra)s/report-preview.html"><img src="%(ra)s/screenshots/dashboard-hero.png" alt="Dashboard overview, light theme"></a>
<div class="callout"><p><strong>Open the live mock-up:</strong> <a href="%(ra)s/report-preview.html"><code>assets/report-preview.html</code></a></p>
<p>Views: Overview, Findings, Frameworks and agent map, Rules, Suppressions, Scan history (this run only), Settings, Help. Use <em>Preview state</em> in the top band to switch between a complete and a partial scan.</p>
<p>Deep links: <code>#findings/F3</code>, <code>#findings/sev=high</code>, <code>#findings/rule=NEX015</code>, <code>#settings</code>.</p></div></div>
<div class="grid">%(dcards)s</div>
<h2 id="wire">Journey wireframes (J1&ndash;J6)</h2>
<p class="sub">Swim-lane storyboards: the screen at each step, the user action, decision points and failure paths with real copy.</p>
<div class="grid">%(wcards)s</div>
<h2 id="screens">Rendered screens</h2>
<p class="sub">Terminal states at 80 and 120 columns, rendered from terminal-mockups.md; GitHub alert, PR check and job summaries; pre-commit failure. HTML sources sit next to each PNG.</p>
<div class="grid">%(scards)s</div>
<h2 id="flows">Flow diagrams</h2><div class="grid">%(fcards)s</div>
<h2 id="docs">Documents</h2>
<table><thead><tr><th>File</th><th>Contents</th></tr></thead><tbody>%(docs)s</tbody></table>
<p class="sub">%(disc)s</p>
</div></body></html>
""" % dict(css=css, mock=MOCK_LABEL, mark=mark_svg(22), ra=REL_ASSETS, dcards="".join(dcards), wcards="".join(wcards),
           scards="".join(scards), fcards="".join(fcards), docs=docs, disc=esc(TOKENS["copy"]["disclaimer"]))
    check_balanced(html_, "design-pack.html")
    check_colours(html_, "design-pack.html")
    check_no_handlers(html_, "design-pack.html")
    check_no_network(html_, "design-pack.html")
    open(os.path.join(DESIGN, "design-pack.html"), "w").write(html_)

    # markdown file list
    lines = ["# nexvul design pack: file list", "",
             "> %s. Generated by `docs/design/_build/pack.py`. Gallery: [`design-pack.html`](design-pack.html)." % MOCK_LABEL, "",
             "Regenerate everything:", "", "```sh",
             "python3 docs/design/_build/dashboard.py --shots   # assets/report-preview.html + assets/screenshots/",
             "python3 docs/design/_build/wireframes.py --shots  # docs/design/wireframes/",
             "python3 docs/design/_build/screens.py             # docs/design/screens/",
             "python3 docs/design/_build/pack.py                # this file and design-pack.html", "```", "",
             "Each generator checks tag balance, that every colour literal exists in `tokens.json`, that there are no",
             "inline event handlers or style attributes (dashboard), and that nothing references the network.", "",
             "## Dashboard app shell", "", "| File | Screen IDs | What it shows |", "|---|---|---|"]
    for f, ids, t in DASH:
        lines.append("| `assets/%s` | %s | %s |" % (f, ids, t))
    lines += ["", "## Journey wireframes", "", "| File | Journey |", "|---|---|"]
    for h in sorted(glob.glob(os.path.join(DESIGN, "wireframes", "*.html"))):
        b = os.path.basename(h)
        lines.append("| `docs/design/wireframes/%s` (+ `.png` preview) | %s |" % (b, b.split("-")[0]))
    lines += ["", "## Rendered screens", "", "| File | Screen ID |", "|---|---|"]
    for h in sorted(glob.glob(os.path.join(DESIGN, "screens", "*.png"))):
        b = os.path.basename(h)
        lines.append("| `docs/design/screens/%s` (+ `.html` source) | %s |" % (b, b.split("-")[0]))
    lines += ["", "## Flow diagrams", ""] + ["- `docs/design/flows/%s`" % os.path.basename(s) for s in sorted(glob.glob(os.path.join(DESIGN, "flows", "*.svg")))]
    lines += ["", "## Documents", ""] + ["- `docs/design/%s` — %s" % d for d in DOCS]
    lines += ["", "## Generators", "", "- `docs/design/_build/common.py` — tokens to CSS, escaping, checks, headless Chrome capture",
              "- `docs/design/_build/dashboard_data.py` — dashboard sample data", "- `docs/design/_build/dashboard.py`",
              "- `docs/design/_build/wireframes.py`", "- `docs/design/_build/screens.py`", "- `docs/design/_build/pack.py`",
              "- `docs/design/_build/flows.py`, `check_widths.py` — earlier pass", ""]
    open(os.path.join(DESIGN, "design-pack.md"), "w").write("\n".join(lines))
    print("wrote design-pack.html, design-pack.md")


if __name__ == "__main__":
    build()
