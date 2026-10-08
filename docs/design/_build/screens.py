"""Renders docs/design/screens/*.html + *.png.

Terminal screens are rendered from the fenced blocks in docs/design/terminal-mockups.md (single source), with
colour applied from tokens.json the way the terminal reporter would (severity SGR equivalents, accent rule IDs,
source/sink role words). The CI plain screen (T15) is rendered with no colour at all, as the product prints it.
GitHub screens are schematic: they show which GitHub region carries which nexvul string; they are not a copy of
GitHub's styling. Run: python3 docs/design/_build/screens.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (ROOT, DESIGN, MOCK_LABEL, esc, css_vars, csp_hash, mark_svg, check_balanced, check_colours,
                    check_no_handlers, check_no_network, shoot, TOKENS)

OUT = os.path.join(DESIGN, "screens")
DK = TOKENS["color"]["dark"]


def parse_mockups():
    blocks, cur, want, buf, infence = {}, None, None, None, False
    for line in open(os.path.join(DESIGN, "terminal-mockups.md")).read().splitlines():
        if line.startswith("## "):
            cur = line[3:].split(" ")[0].split("/")[0]
        m = re.match(r"<!-- cols:(\d+) -->", line)
        if m:
            want = int(m.group(1))
            continue
        if line.startswith("```") and want and not infence:
            infence, buf = True, []
            continue
        if line.startswith("```") and infence:
            blocks.setdefault(cur, []).append((want, "\n".join(buf)))
            infence, want = False, None
            continue
        if infence:
            buf.append(line)
    return blocks


TOK = re.compile(
    r"(?P<crit>CRITICAL\s+(?:████|\[####\]))|(?P<high>HIGH\s+(?:███░|\[###\.\]))|(?P<med>MEDIUM\s+(?:██░░|\[##\.\.\]))"
    r"|(?P<low>LOW\s+(?:█░░░|\[#\.\.\.\]))|(?P<sevword>\b(?:CRITICAL|HIGH)\b)|(?P<rid>\bNEX\d{3}\b)"
    r"|(?P<src>(?<=\d )source\b)|(?P<sink>(?<=\d )sink\b)|(?P<err>config error|error:|Failed|NOT APPLIED|refusing)"
    r"|(?P<res>^\s?Result\b)|(?P<prompt>^\$ )")


def colour_line(line, plain):
    if plain:
        return esc(line)
    s = line.strip()
    if s.startswith("PARTIAL SCAN") or s.startswith("health."):
        return '<span class="t-partial">%s</span>' % esc(line)
    if "SCAN FAILED" in line:
        return esc(line).replace("SCAN FAILED", '<span class="t-failed">SCAN FAILED</span>')
    if s and re.fullmatch(r"[A-Z][A-Z &()/,-]+", s) and len(s) > 3:
        return '<span class="t-bold">%s</span>' % esc(line)
    m = re.match(r"^(\s*)(ok|warn|fail|info)(\s)", line)
    if m:
        cls = {"ok": "t-bold", "warn": "t-med", "fail": "t-crit-t", "info": "t-dim"}[m.group(2)]
        return m.group(1) + '<span class="%s">%s</span>' % (cls, m.group(2)) + colour_rest(line[m.end(2):])
    if line.startswith("nexvul ") and "  " in line:
        return '<span class="t-bold">nexvul</span>' + colour_rest(line[6:])
    if re.match(r"^\s{2}(Files|Frameworks|Rules|Mode|Config|Scope)\s", line):
        m = re.match(r"^(\s{2}\S+)(.*)$", line)
        return '<span class="t-dim">%s</span>%s' % (esc(m.group(1)), colour_rest(m.group(2)))
    return colour_rest(line)


def colour_rest(text):
    out, last = [], 0
    cls = {"crit": "t-crit", "high": "t-high", "med": "t-med", "low": "t-low", "sevword": "t-high", "rid": "t-rid",
           "src": "t-src", "sink": "t-sink", "err": "t-crit-t", "res": "t-bold", "prompt": "t-dim"}
    for m in TOK.finditer(text):
        out.append(esc(text[last:m.start()]))
        out.append('<span class="%s">%s</span>' % (cls[m.lastgroup], esc(m.group(0))))
        last = m.end()
    out.append(esc(text[last:]))
    return "".join(out)


T = DK
TERM_CSS = """
.term{background:%(bg)s;color:%(fg)s;border-radius:10px;overflow:hidden;border:1px solid %(bd)s;display:inline-block}
.tbar{display:flex;gap:6px;align-items:center;padding:8px 12px;background:%(bar)s;color:%(dim)s;font:12px var(--body)}
.tbar i{width:10px;height:10px;border-radius:5px;background:%(bd)s;display:inline-block}
.tbar span{margin-left:8px}
.term pre{margin:0;padding:14px 16px 16px;font:13px/1.45 var(--mono);white-space:pre}
.term pre.c80{width:calc(80ch + 32px)}.term pre.c120{width:calc(120ch + 32px)}
.t-dim{color:%(dim)s}.t-bold{font-weight:700}.t-rid{color:%(acc)s}
.t-crit{background:%(cf)s;color:%(con)s;font-weight:700}
.t-crit-t{color:%(crit)s;font-weight:700}
.t-high{color:%(crit)s;font-weight:700}
.t-med{color:%(med)s}.t-low{color:%(low)s}
.t-src{color:%(src)s}.t-sink{color:%(sink)s}
.t-partial{background:%(pf)s;color:%(pon)s;font-weight:700}
.t-failed{background:%(cf)s;color:%(con)s;font-weight:700}
""" % dict(bg=T["surface"]["page"], fg=T["text"]["default"]["value"], bd=T["border"]["default"], bar=T["surface"]["raised"],
           dim=T["text"]["muted"]["value"], acc=T["accent"]["text"]["value"], cf=T["status"]["failed"]["fill"],
           con=T["status"]["failed"]["on_fill"], crit=T["severity"]["critical"]["text"], med=T["severity"]["medium"]["text"],
           low=T["severity"]["low"]["text"], src=T["flow"]["source_marker"], sink=T["flow"]["sink_marker"],
           pf=T["status"]["partial"]["fill"], pon=T["status"]["partial"]["on_fill"])

PAGE_CSS = """
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.5 var(--body)}
.frame{display:inline-block;padding:20px 24px 24px}
.lab{display:flex;gap:10px;align-items:baseline;margin:0 0 10px;font-size:13px}
.lab .id{font-family:var(--mono);font-weight:700;color:var(--accent-text)}
.lab .t{font-weight:650}
.lab .mock{margin-left:16px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mock-band-text);background:var(--mock-band);padding:1px 8px;border-radius:4px}
.cap{margin:10px 0 0;font-size:12px;color:var(--muted);max-width:110ch}
.gh{width:1000px;border:1px solid var(--border-strong);border-radius:10px;background:var(--card);overflow:hidden;font-size:14px}
.ghtop{display:flex;gap:10px;align-items:center;padding:10px 16px;background:var(--inset);border-bottom:1px solid var(--border);color:var(--muted);font-size:13px}
.ghtop .crumb{font-weight:600;color:var(--text)}
.ghb{padding:16px 20px}
.ghb h2{font-size:20px;margin:0 0 6px}
.chip{display:inline-block;font-size:12px;border:1px solid var(--border-strong);border-radius:12px;padding:1px 10px;margin-right:6px;color:var(--muted)}
.chip.sev{color:var(--failed-on);background:var(--failed-fill);border-color:var(--failed-fill);font-weight:700}
.chip.open{color:var(--text);font-weight:600}
.region{position:relative;border:1px dashed var(--accent);border-radius:8px;padding:12px 14px;margin:14px 0 0;background:var(--card)}
.region>.rl{position:absolute;top:-10px;left:10px;background:var(--card);padding:0 6px;font:600 11px var(--mono);color:var(--accent-text)}
.mono{font-family:var(--mono);font-size:12.5px}
.code{background:var(--inset);border:1px solid var(--border);border-radius:6px;padding:8px 10px;font:12.5px/1.5 var(--mono);white-space:pre;overflow:hidden}
.code .hl{background:var(--sev-critical-tint);display:block}
.paths{list-style:none;margin:6px 0 0;padding:0}
.paths li{display:grid;grid-template-columns:28px 160px 1fr;gap:8px;padding:6px 0;border-top:1px solid var(--border-subtle);align-items:center;font-size:13px}
.paths .n{display:inline-flex;width:22px;height:22px;border-radius:11px;border:2px solid var(--border-strong);align-items:center;justify-content:center;font-size:11px;font-weight:700}
.list{border:1px solid var(--border);border-radius:8px;overflow:hidden}
.list .r{display:grid;grid-template-columns:1fr 110px 90px;gap:10px;padding:10px 14px;border-top:1px solid var(--border-subtle);align-items:center}
.list .r:first-child{border-top:0;background:var(--inset);font-size:12px;color:var(--muted)}
.checks .r{display:grid;grid-template-columns:24px 1fr 120px;gap:10px;padding:10px 14px;border-top:1px solid var(--border-subtle);align-items:center}
.st{font:700 11px var(--mono);letter-spacing:.04em}
.st-fail{color:var(--sev-critical)} .st-ok{color:var(--muted)}
.x{width:16px;height:16px;border-radius:8px;border:2px solid var(--sev-critical);display:inline-block}
.o{width:16px;height:16px;border-radius:8px;border:2px solid var(--border-strong);display:inline-block}
.md h3{font-size:16px;margin:16px 0 6px}
.md h2{font-size:20px;margin:0 0 8px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.md table{border-collapse:collapse;font-size:13px;margin:6px 0}
.md th,.md td{border:1px solid var(--border);padding:5px 10px;text-align:left}
.md th{background:var(--inset)}
.md code{font:12px var(--mono);background:var(--inset);padding:1px 5px;border-radius:4px;border:1px solid var(--border-subtle)}
.md blockquote{margin:8px 0;padding:6px 12px;border-left:4px solid var(--partial-fill);color:var(--text)}
.md sub{color:var(--muted)}
"""


def wrap_page(sid, title, body, caption, extra_css=""):
    css = css_vars() + PAGE_CSS + TERM_CSS + extra_css
    csp = "default-src 'none'; style-src %s; base-uri 'none'" % csp_hash(css)
    h = """<!doctype html>
<html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="%s"><title>%s %s</title><style>%s</style></head>
<body><div class="frame"><p class="lab"><span class="id">%s</span><span class="t">%s</span><span class="mock">%s</span></p>
%s
<p class="cap">%s</p></div></body></html>
""" % (csp, esc(sid), esc(title), css, esc(sid), esc(title), MOCK_LABEL, body, caption)
    return h


def term_html(text, cols, title, plain=False):
    lines = text.split("\n")
    over = [l for l in lines if len(l) > cols]
    if over:
        raise SystemExit("%s: line exceeds %d cols: %r" % (title, cols, over[0]))
    pre = "\n".join(colour_line(l, plain) for l in lines)
    return ('<div class="term"><div class="tbar"><i></i><i></i><i></i><span>%s &middot; %d columns</span></div>'
            '<pre class="c%d">%s</pre></div>' % (esc(title), cols, cols, pre))


U03_120 = """NEX002  External content indexed into a vector store
        ASI06 Memory & Context Poisoning · default severity high
        confidence high (same function) / medium (across files)

WHAT IT LOOKS FOR
  Text fetched from outside the application (HTTP responses, web loaders, email, uploaded files) that reaches a
  vector-store write such as add_documents, add_texts, upsert or from_documents, with no validation or trust-boundary
  step that nexvul recognises in between.

WHY IT MATTERS
  Documents in a vector store are retrieved later and placed in the model's context. Text an attacker controls on a
  web page can carry instructions that the agent follows on a future, unrelated request.

EXAMPLE (flagged)                                          EXAMPLE (not flagged)
  html = requests.get(url).text                              if urlparse(url).hostname not in ALLOWED_SOURCES:
  vector_store.add_documents(                                    raise ValueError("source not allowed")
      [Document(page_content=html)])                         doc = Document(page_content=html,
                                                                            metadata={"source": url, "trust": "web"})

HOW TO FIX
  Allowlist the sources you index. Record provenance on every stored document. Keep retrieved text in user or tool
  messages with delimiters, never in system instructions.

WHAT THIS RULE DOES NOT DETECT
  Poisoned documents already in the corpus. Poisoning of embeddings or the model. Ingestion code outside the scanned
  repository. Validation helpers nexvul does not recognise are treated as absent (possible false positive).

SUPPRESSING THIS FINDING
  # nexvul: ignore[NEX002] -- <why this source is trusted>        In CI the justification after -- is required.

REFERENCES
  OWASP Top 10 for Agentic Applications 2026, ASI06 · docs/rules/NEX002.md"""


def terminal_screens(B):
    # (screen id, slug, title, section, block index per width; None = reuse the 80 block in a 120 window)
    spec = [
        ("T02", "clean-with-caveats", "Complete, no findings (clean with caveats)", "T02", {80: 0, 120: 1}),
        ("T04", "findings", "Complete, findings at or above threshold", "T04", {80: 0, 120: 1}),
        ("T05", "partial-scan", "Partial scan, with findings (tail)", "T05", {80: 0, 120: 1}),
        ("T09", "config-error", "Config error", "T09", {80: 0, 120: 0}),
        ("U03", "explain", "nexvul explain NEX002", "U03", {80: 0, 120: "U03_120"}),
        ("U01", "rules", "nexvul rules", "U01", {80: 1, 120: 0}),
        ("U05", "doctor", "nexvul doctor (pass)", "U05", {80: 0, 120: 0}),
        ("U06", "doctor-problems", "nexvul doctor (problems)", "U06", {80: 0, 120: 0}),
        ("T15", "ci-plain", "Plain output in CI (no colour, ASCII meters)", "T15", {80: 0, 120: 0}),
        ("K02", "pre-commit-failure", "pre-commit: findings block the commit", "K02", {80: 0}),
    ]
    out = []
    for sid, slug, title, sec, widths in spec:
        for cols, idx in widths.items():
            text = U03_120 if idx == "U03_120" else B[sec][idx][1]
            reused = cols == 120 and isinstance(idx, int) and B[sec][idx][0] == 80
            plain = sid == "T15"
            cap = ("Rendered from terminal-mockups.md %s. %s" % (sid, "Plain mode: zero ESC bytes, ASCII meter, no colour."
                                                                 if plain else "Colour per tokens.json terminal SGR; every meaning is also in words."))
            if reused:
                cap += " Same output at 120 columns: this screen has no wide layout, so a wider terminal only adds space."
            body = term_html(text, cols, "Terminal (CI log)" if plain else "Terminal", plain)
            name = "%s-%s-%d" % (sid, slug, cols)
            out.append((name, wrap_page(sid, "%s, %d columns" % (title, cols), body, cap)))
    return out


def gh_screens():
    g02 = """<div class="gh"><div class="ghtop"><span class="crumb">my-org / my-agent-project</span><span>Security</span><span>Code scanning</span><span>Alert #41</span></div>
<div class="ghb">
<h2>Financial action without human oversight</h2>
<span class="chip open">Open</span><span class="chip">in main</span><span class="chip sev">Critical</span><span class="chip">Tool: nexvul</span><span class="chip">Rule ID: NEX018</span>
<div class="region"><span class="rl">G02 message.text</span>
<p class="mono">CRITICAL · Tool refund_order calls stripe.Refund.create() with an amount chosen by the model. No approval step was found on the path in the scanned code; controls outside this repository are not visible to nexvul. Confidence: medium. Steps: 3 (Show paths).</p></div>
<div class="region"><span class="rl">G02 location + snippet (untrusted text, escaped)</span>
<p class="mono">agent/billing.py:58</p>
<div class="code">56      order = Order.get(order_id)
57      amt = int(amount * 100)
<span class="hl">58      stripe.Refund.create(charge=order.charge_id, amount=amt)</span></div></div>
<div class="region"><span class="rl">G02 Show paths (codeFlows)</span>
<ul class="paths"><li><span class="n">1</span><span class="mono">agent/billing.py:31</span><span>source: tool argument chosen by the model</span></li>
<li><span class="n">2</span><span class="mono">agent/billing.py:44</span><span>step</span></li>
<li><span class="n">3</span><span class="mono">agent/billing.py:58</span><span>sink: financial action</span></li></ul></div>
<div class="region"><span class="rl">G03 rule help (help.markdown, built-in text only)</span>
<p><strong>Financial action without human oversight</strong> · ASI02 Tool Misuse · ASI09 (provisional)</p>
<p>A finding means nexvul identified a risky pattern. It does not prove the code is exploitable.</p>
<p class="mono">What nexvul looked for · Why it matters · How to fix · What this rule does not detect · Severity and confidence · Triage · Suppressing this finding · References</p>
<p class="mono"># nexvul: ignore[NEX018] -- &lt;why this is mitigated&gt;</p></div>
</div></div>"""
    g01 = """<div class="gh"><div class="ghtop"><span class="crumb">my-org / my-agent-project</span><span>Security</span><span>Code scanning</span></div>
<div class="ghb"><p class="mono">is:open tool:nexvul</p>
<div class="list"><div class="r"><span>Alert</span><span>Severity</span><span>Rule</span></div>
<div class="r"><span><strong>Financial action without human oversight</strong><br><span class="mono">agent/billing.py:58</span></span><span>Critical</span><span class="mono">NEX018</span></div>
<div class="r"><span><strong>Dangerous capability combination (shell/code-exec + unrestricted network)</strong><br><span class="mono">agent/tools.py:18</span></span><span>High</span><span class="mono">NEX020</span></div>
<div class="r"><span><strong>External content indexed into a vector store</strong><br><span class="mono">agent/ingest.py:42</span></span><span>High</span><span class="mono">NEX002</span></div>
<div class="r"><span><strong>MCP connection without authentication or over cleartext</strong><br><span class="mono">mcp.json:12</span></span><span>High</span><span class="mono">NEX007</span></div>
</div>
<div class="region"><span class="rl">G05 tool status (run notifications)</span><p>nexvul · last scan: 312 of 312 files analysed · rules sha256:9c1e… · no configuration notifications</p></div>
</div></div>"""
    a05 = """<div class="gh"><div class="ghtop"><span class="crumb">Pull request #212</span><span>Add refund tool</span><span>Checks</span></div>
<div class="ghb"><h2>Some checks were not successful</h2>
<div class="list checks"><div class="r"><span class="x" aria-hidden="true"></span><span><strong>nexvul / scan</strong> (pull_request)<br><span class="mono">nexvul: 3 findings at or above high</span></span><span class="st st-fail">FAILING · REQUIRED</span></div>
<div class="r"><span class="x" aria-hidden="true"></span><span><strong>Code scanning results / nexvul</strong><br><span class="mono">3 new alerts including 1 critical</span></span><span class="st st-fail">FAILING</span></div>
<div class="r"><span class="o" aria-hidden="true"></span><span><strong>tests / unit</strong></span><span class="st st-ok">SUCCESSFUL</span></div></div>
<div class="region"><span class="rl">A05 step error annotation (trusted string)</span><p class="mono">nexvul: 3 findings at or above high</p></div>
<div class="region"><span class="rl">A05 partial variant</span><p class="mono">nexvul: PARTIAL SCAN — 4 of 312 files not analysed</p></div>
<p class="cap">The README tells users to require the <strong>nexvul job</strong>: only the job also fails on partial scans. Status words are written out; the check icon is never the only signal.</p>
</div></div>"""
    a01 = """<div class="gh"><div class="ghtop"><span class="crumb">Actions</span><span>nexvul</span><span>Summary</span></div>
<div class="ghb md">
<h2>nexvul — 3 findings at or above <code>high</code></h2>
<p><strong>Scan complete.</strong> 312 of 312 files analysed · 25 of 25 rules · fail-on <code>high</code> · exit code 1</p>
<table><tr><th>Severity</th><th>Count</th></tr><tr><td>████ Critical</td><td>1</td></tr><tr><td>███░ High</td><td>2</td></tr><tr><td>██░░ Medium</td><td>1</td></tr><tr><td>█░░░ Low</td><td>1</td></tr><tr><td>Suppressed</td><td>1</td></tr></table>
<h3>Findings at or above <code>high</code></h3>
<table><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Title</th></tr>
<tr><td>████ Critical</td><td>NEX018</td><td><code>agent/billing.py:58</code></td><td>Financial action without human oversight</td></tr>
<tr><td>███░ High</td><td>NEX002</td><td><code>agent/ingest.py:42</code></td><td>External content indexed into a vector store</td></tr>
<tr><td>███░ High</td><td>NEX007</td><td><code>mcp.json:12</code></td><td>MCP connection without authentication or over cleartext</td></tr></table>
<p>Evidence, flow and fixes: <strong>Security → Code scanning</strong>, filter <code>tool:nexvul</code>. Learn a rule locally: <code>nexvul explain NEX018</code>.</p>
<h3>Suppressions added in this pull request (1)</h3>
<table><tr><th>Rule</th><th>Location</th><th>Justification</th></tr><tr><td>NEX006</td><td><code>agent/server.py:41</code></td><td><code>auth enforced by the API gateway (infra/gateway.tf, route /agents/*)</code></td></tr></table>
<h3>Configuration</h3>
<p>Effective config: <code>.nexvul.yml</code> at base <code>3f2c1a9</code>. Protections weakened by repository configuration: none.</p>
<p><sub>nexvul 0.1.0 · rules sha256:9c1e… · A clean nexvul result does not prove that an application is secure.</sub></p>
</div></div>"""
    a03 = """<div class="gh"><div class="ghtop"><span class="crumb">Actions</span><span>nexvul</span><span>Summary</span></div>
<div class="ghb md">
<h2>nexvul — PARTIAL SCAN: 4 of 312 files not analysed</h2>
<blockquote><strong>This result is not a clean bill of health.</strong> Code in the files below was not checked. The job fails until the scan is complete or trusted configuration excludes these files.</blockquote>
<table><tr><th>Reason</th><th>Files</th><th>Examples</th></tr><tr><td>parse error</td><td>2</td><td><code>agent/legacy.py</code>, <code>tools/gen_api.py</code></td></tr>
<tr><td>over size limit (1 MB)</td><td>1</td><td><code>data/fixtures.py</code></td></tr><tr><td>parser timeout (30 s)</td><td>1</td><td><code>agent/huge_graph.py</code></td></tr></table>
<p><strong>Findings in analysed files:</strong> 1 critical, 2 high, 1 medium (3 at or above <code>high</code>) — Security → Code scanning.</p>
<p><strong>What to do:</strong> fix the parse errors, or add generated files to <code>exclude</code> in <code>.nexvul.yml</code> on the default branch (exclusions are counted in every report). Do not add <code>continue-on-error</code>; it hides partial scans.</p>
<p><sub>nexvul 0.1.0 · exit code 3 (scan incomplete) · rules sha256:9c1e…</sub></p>
</div></div>"""
    note = ("Schematic of the GitHub regions nexvul writes into, with nexvul's real strings. Not GitHub's actual styling; "
            "region labels name the screen ID and the SARIF or summary field. Spec: github-and-action.md.")
    return [
        ("G01-alert-list", wrap_page("G01 G05", "Code scanning alert list and tool status", g01, note)),
        ("G02-alert-detail", wrap_page("G02 G03", "Code scanning alert detail, Show paths and rule help", g02, note)),
        ("A05-pr-check", wrap_page("A05", "Pull request checks and job conclusion", a05, note)),
        ("A01-job-summary", wrap_page("A01", "Job summary: findings at or above threshold (exit 1)", a01, note)),
        ("A03-job-summary-partial", wrap_page("A03", "Job summary: partial scan (exit 3)", a03, note)),
    ]


def build():
    os.makedirs(OUT, exist_ok=True)
    B = parse_mockups()
    pages = terminal_screens(B) + gh_screens()
    for name, h in pages:
        check_balanced(h, name)
        check_colours(h, name)
        check_no_handlers(h, name)
        check_no_network(h, name)
        p = os.path.join(OUT, name + ".html")
        open(p, "w").write(h)
        shoot("file://" + p, os.path.join(OUT, name + ".png"), 1600, 2200, crop=False)
        crop_box(os.path.join(OUT, name + ".png"))
        print("screen", name)
    return [n for n, _ in pages]


def crop_box(path, pad=8):
    from PIL import Image, ImageChops
    im = Image.open(path).convert("RGB")
    bg = Image.new("RGB", im.size, im.getpixel((im.width - 1, im.height - 1)))
    bb = ImageChops.difference(im, bg).getbbox()
    if bb:
        im.crop((0, 0, min(im.width, bb[2] + 24 + pad), min(im.height, bb[3] + 24 + pad))).save(path)


if __name__ == "__main__":
    build()
