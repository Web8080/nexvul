"""Generates assets/report-preview.html: the v1 local dashboard app shell (DEC-0009).

Run:  python3 docs/design/_build/dashboard.py [--shots]

View switching: progressive enhancement. Without JavaScript every view renders one after another and the
menu links are in-page anchors (H10: the report is complete with scripts blocked). The hashed script adds
class "js" to <html>, shows one view at a time from location.hash (#overview, #findings, #findings/F3,
#findings/sev=high, #agents, #rules, #suppressions, #history, #settings, #help) and wires filters, the
narrow menu, theme and copy buttons. No inline event-handler attributes; no style attributes (CSP).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (ROOT, MOCK_LABEL, SEV_ORDER, METER, LABEL, esc, show_ctl, trunc, css_vars, csp_hash,
                    mark_svg, check_balanced, check_colours, check_no_handlers, check_no_network, shoot,
                    TOKENS)
import dashboard_data as D

OUT = os.path.join(ROOT, "assets", "report-preview.html")
SHOTS = os.path.join(ROOT, "assets", "screenshots")

S = D.SCAN
FIND = D.FINDINGS
COUNTS = {k: sum(1 for f in FIND if f["sev"] == k) for k in SEV_ORDER}
AT_OR_ABOVE = sum(1 for f in FIND if SEV_ORDER.index(f["sev"]) <= SEV_ORDER.index(S["fail_on"]))
RULE_TITLE = {r[0]: r[1] for r in D.RULES}
APPLIED_SUPP = sum(1 for s in D.SUPPRESSIONS if s["status"] in ("applied", "applied-nojust"))


# ------------------------------------------------------------------ small components

def sev_badge(sev, compact=False):
    return ('<span class="sev sev-%s"><span class="sev-word">%s</span><span class="meter" aria-hidden="true">'
            '%s</span></span>') % (sev, LABEL[sev], METER[sev])


def code(s, cls=""):
    return '<code class="%s">%s</code>' % (cls, show_ctl(s))


def loc(path, line, col=None):
    t = "%s:%d" % (path, line) + (":%d" % col if col else "")
    return '<code class="loc">%s</code>' % show_ctl(trunc(t, TOKENS["truncation"]["path_display_max"]))


def asi_tags(asis, prov=False):
    out = "".join('<span class="tag" title="%s">%s</span>' % (esc(D.ASI_NAMES.get(a, a)), a) for a in asis)
    if prov:
        out += '<span class="tag tag-prov" title="ASI label pending mapping decision OD-02">provisional</span>'
    return out


def copy_block(text, label="Copy"):
    return ('<div class="copyrow"><pre class="cmd"><code>%s</code></pre>'
            '<button type="button" class="btn btn-sm copy" data-copy="%s">%s</button></div>') % (
        show_ctl(text), esc(text), label)


ICONS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>'
                '<rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    "findings": '<path d="M4 6h16M4 12h16M4 18h10"/>',
    "agents": '<circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/>'
              '<path d="M7.3 11 16.7 6M7.3 13l9.4 5"/>',
    "rules": '<path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7"/>',
    "suppressions": '<path d="M12 3v4M12 17v4M4.9 4.9l2.8 2.8M16.3 16.3l2.8 2.8"/><circle cx="12" cy="12" r="4"/>',
    "history": '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    "settings": '<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/>',
    "help": '<circle cx="12" cy="12" r="8.5"/><path d="M9.8 9.5a2.3 2.3 0 1 1 3.2 2.1c-.7.3-1 .8-1 1.5V14"/>'
            '<path d="M12 17.2v.1"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "theme": '<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5v17A8.5 8.5 0 0 0 12 3.5z" fill="currentColor"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
}


def icon(name, size=18):
    return ('<svg class="ico" viewBox="0 0 24 24" width="%d" height="%d" fill="none" stroke="currentColor" '
            'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">%s</svg>') % (
        size, size, ICONS[name])


NAV = [
    ("Report", [("overview", "Overview", ""), ("findings", "Findings", str(len(FIND))),
                ("agents", "Frameworks and agent map", str(len(D.FRAMEWORKS))),
                ("rules", "Rules", "%d/%d" % (S["rules_run"], S["rules_total"])),
                ("suppressions", "Suppressions", str(len(D.SUPPRESSIONS)))]),
    ("This run", [("history", "Scan history", "1")]),
    ("Preferences", [("settings", "Settings", ""), ("help", "Help and docs", "")]),
]

VIEW_TITLES = {v[0]: v[1] for _, items in NAV for v in items}


def nav():
    out = ['<nav class="nav" id="nav" aria-label="Report sections">',
           '<div class="nav-head">%s<span class="wordmark">nexvul</span>'
           '<button type="button" class="btn-icon nav-close" id="navClose" aria-label="Close menu">%s</button></div>'
           % (mark_svg(22), icon("close"))]
    for group, items in NAV:
        out.append('<div class="nav-group"><div class="nav-label">%s</div><ul>' % esc(group))
        for vid, label, count in items:
            c = '<span class="nav-count">%s</span>' % esc(count) if count else ""
            out.append('<li><a class="nav-link" href="#%s" data-view="%s">%s<span class="nav-text">%s</span>%s</a></li>'
                       % (vid, vid, icon(vid), esc(label), c))
        out.append("</ul></div>")
    out.append('<div class="nav-foot"><p><strong>Local file.</strong> No account, no sign-in, no network. '
               'Opened from your disk; nothing leaves this machine.</p>'
               '<p class="dim">nexvul %s &middot; rules %s</p></div></nav>' % (S["version"], S["rules_pack"]))
    return "".join(out)


def topbar():
    return """
<header class="topbar">
  <button type="button" class="btn-icon menu-btn" id="menuBtn" aria-controls="nav" aria-expanded="false" aria-label="Open menu">%(menu)s</button>
  <div class="target">
    <span class="target-label">Scan target</span>
    <span class="target-val"><code>%(target)s</code><span class="sep" aria-hidden="true">&middot;</span><span class="meta">commit <code>%(commit)s</code></span><span class="sep" aria-hidden="true">&middot;</span><span class="meta">%(ended)s</span></span>
  </div>
  <div class="topbar-right">
    <a class="status-pill status-complete only-complete" href="#history" title="Scan completeness">
      <span class="status-word">COMPLETE</span><span class="status-detail">%(fa)d of %(fd)d files analysed</span></a>
    <a class="status-pill status-partial only-partial" href="#history" title="Scan completeness">
      <span class="status-word">PARTIAL SCAN</span><span class="status-detail">%(na)d of %(fd)d files not analysed</span></a>
    <span class="exit-chip only-complete" title="Exit code of this run">exit 1</span>
    <span class="exit-chip only-partial" title="Exit code of this run">exit 3</span>
    <button type="button" class="btn btn-ghost theme-btn" id="themeBtn" aria-label="Change theme">%(theme)s<span id="themeLabel">Theme: system</span></button>
  </div>
</header>""" % dict(menu=icon("menu"), target=esc(S["target"]), commit=esc(S["commit"]), ended=esc(S["ended"]),
                    fa=S["files_analysed"], fd=S["files_discovered"], na=D.PARTIAL["not_analysed"],
                    theme=icon("theme", 16))


def partial_banner():
    p = D.PARTIAL
    return ('<div class="banner-partial only-partial" role="alert"><strong>PARTIAL SCAN</strong> &mdash; %d of %d '
            'files not analysed. This result is not a clean bill of health. '
            '<a href="#history">See what was not analysed</a></div>') % (p["not_analysed"], S["files_discovered"])


def view_head(vid, sub):
    return ('<div class="view-head"><h1>%s</h1><p class="sub">%s</p></div>' % (esc(VIEW_TITLES[vid]), sub))


# ------------------------------------------------------------------ views

def v_overview():
    tiles = []
    tiles.append('<a class="tile tile-status" href="#history"><span class="tile-label">Status</span>'
                 '<span class="tile-num only-complete">Complete</span><span class="tile-num only-partial">Partial</span>'
                 '<span class="tile-foot only-complete">%d of %d files</span>'
                 '<span class="tile-foot only-partial">%d of %d files</span></a>'
                 % (S["files_analysed"], S["files_discovered"], D.PARTIAL["analysed"], S["files_discovered"]))
    tiles.append('<a class="tile" href="#findings"><span class="tile-label">Findings</span><span class="tile-num">%d'
                 '</span><span class="tile-foot">%d at or above %s</span></a>' % (len(FIND), AT_OR_ABOVE, S["fail_on"]))
    for k in SEV_ORDER[:4]:
        tiles.append('<a class="tile tile-sev tile-%s" href="#findings/sev=%s"><span class="tile-label">%s '
                     '<span class="meter" aria-hidden="true">%s</span></span><span class="tile-num">%d</span>'
                     '<span class="tile-foot">%s</span></a>'
                     % (k, k, LABEL[k], METER[k], COUNTS[k],
                        "fails the build" if TOKENS["severity"][k]["fails_at_default_threshold"] else "below fail-on"))
    tiles.append('<a class="tile" href="#suppressions"><span class="tile-label">Suppressed</span><span class="tile-num">'
                 '%d</span><span class="tile-foot">1 rejected &middot; 1 stale</span></a>' % APPLIED_SUPP)

    # distribution bar (SVG, labelled; never the only carrier: tiles carry the numbers)
    total = len(FIND)
    x, segs, legend = 0.0, [], []
    for k in SEV_ORDER[:4]:
        w = 100.0 * COUNTS[k] / total
        if w:
            segs.append('<rect class="seg seg-%s" x="%.2f" y="0" width="%.2f" height="10"/>' % (k, x, max(w - 0.6, 0.5)))
        x += w
        legend.append('<li><span class="sw sw-%s" aria-hidden="true"></span>%s %d</li>' % (k, LABEL[k].title(), COUNTS[k]))
    dist = ('<div class="dist"><svg viewBox="0 0 100 10" preserveAspectRatio="none" role="img" '
            'aria-label="Findings by severity: %s">%s</svg><ul class="legend">%s</ul></div>'
            % (", ".join("%d %s" % (COUNTS[k], k) for k in SEV_ORDER[:4]), "".join(segs), "".join(legend)))

    strip = ('<section class="strip" aria-label="What was checked"><div class="strip-label">What was checked</div>'
             '<ul class="strip-items">'
             '<li class="only-complete"><strong>%d/%d</strong> files analysed</li>'
             '<li class="only-partial strip-warn"><strong>%d/%d</strong> files analysed &middot; %d not analysed</li>'
             '<li><strong>%d/%d</strong> rules run</li>'
             '<li>LangGraph, LangChain, OpenAI Agents SDK, MCP</li>'
             '<li>cross-file flows on</li>'
             '<li>%d dynamic imports not followed</li>'
             '<li>%d files excluded by config (counted)</li></ul>'
             '<a class="strip-link" href="#history">Full completeness and provenance</a></section>'
             % (S["files_analysed"], S["files_discovered"], D.PARTIAL["analysed"], S["files_discovered"],
                D.PARTIAL["not_analysed"], S["rules_run"], S["rules_total"], S["dynamic_not_followed"], S["excluded"]))

    top = []
    for f in FIND[:5]:
        top.append('<li><a class="toprow" href="#findings/%s">%s<span class="rid">%s</span><span class="ttl">%s</span>'
                   '%s</a></li>' % (f["id"], sev_badge(f["sev"]), f["rule"], esc(RULE_TITLE[f["rule"]]),
                                    loc(f["path"], f["line"])))

    asi_counts = {}
    for f in FIND:
        for a in f["asi"]:
            asi_counts[a] = asi_counts.get(a, 0) + 1
    mx = max(asi_counts.values())
    asi_rows = "".join(
        '<li><span class="asi-id">%s</span><span class="asi-name">%s</span><span class="asi-bar" aria-hidden="true">'
        '<svg viewBox="0 0 100 8" preserveAspectRatio="none"><rect x="0" y="0" width="%.1f" height="8" rx="1"/></svg>'
        '</span><span class="asi-n">%d</span></li>'
        % (a, esc(D.ASI_NAMES[a]), 100.0 * n / mx, n) for a, n in sorted(asi_counts.items()))

    return """
<section class="view" id="overview" aria-labelledby="h-overview">
  %(banner)s
  <div class="view-head"><h1 id="h-overview">Overview</h1>
    <p class="sub">Scan of <code>%(target)s</code> on branch <code>%(branch)s</code> &middot; fail-on <strong>%(fail_on)s</strong> &middot; local run</p></div>
  <p class="result-line only-complete"><strong>%(at)d findings at or above fail-on (%(fail_on)s).</strong> Exit code 1. %(n)d findings in total; %(supp)d suppressed.</p>
  <p class="result-line only-partial"><strong>%(at)d findings at or above fail-on (%(fail_on)s) in the files that were analysed.</strong> Exit code 3 (scan incomplete).</p>
  <div class="tiles">%(tiles)s</div>
  %(dist)s
  %(strip)s
  <div class="grid-2">
    <section class="panel" aria-labelledby="h-top"><div class="panel-head"><h2 id="h-top">Top findings</h2><a href="#findings">All %(n)d findings</a></div>
      <ul class="toplist">%(top)s</ul></section>
    <div class="stack">
      <section class="panel" aria-labelledby="h-asi"><div class="panel-head"><h2 id="h-asi">By OWASP ASI category</h2></div>
        <ul class="asi-list">%(asi)s</ul>
        <p class="note">A finding can carry more than one ASI tag. Counts are findings, not coverage of a category.</p></section>
      <section class="panel" aria-labelledby="h-sup"><div class="panel-head"><h2 id="h-sup">Suppressions</h2><a href="#suppressions">Review</a></div>
        <p class="kv"><strong>%(supp)d</strong> applied &middot; <strong>1</strong> rejected (hidden character) &middot; <strong>1</strong> stale</p>
        <p class="note">3 suppressions were added on this branch. Suppressions are claims made in the scanned code; review the justifications.</p></section>
    </div>
  </div>
  <p class="disclaimer">%(finding_meaning)s %(disclaimer)s</p>
</section>""" % dict(banner=partial_banner(), target=esc(S["target"]), branch=esc(S["branch"]), fail_on=S["fail_on"],
                     at=AT_OR_ABOVE, n=len(FIND), supp=APPLIED_SUPP, tiles="".join(tiles), dist=dist, strip=strip,
                     top="".join(top), asi=asi_rows, finding_meaning=esc(TOKENS["copy"]["finding_meaning"]),
                     disclaimer=esc(TOKENS["copy"]["disclaimer"]))


def finding_card(f, open_=False):
    flow = ""
    if f["flow"]:
        steps = []
        for i, (role, p, ln, src, note) in enumerate(f["flow"], 1):
            role_word = role if role in ("source", "sink") else "step"
            steps.append('<li class="step step-%s"><span class="step-n">%d</span><span class="role role-%s">%s</span>'
                         '%s<span class="step-note">%s</span><div class="step-code">%s</div></li>'
                         % (role_word, i, role_word, role_word, loc(p, ln), esc(note),
                            code(trunc(src, 140), "snip")))
        flow = '<h4>Flow <span class="dim">(%d steps, source to sink)</span></h4><ol class="flow">%s</ol>' % (
            len(f["flow"]), "".join(steps))
    else:
        flow = ('<h4>Location</h4><p class="nf">%s <span class="dim">Configuration finding: no data flow to show.</span></p>'
                % loc(f["path"], f["line"], f["col"]))
    locs = sorted({(p, ln) for _, p, ln, _, _ in f["flow"]} | {(f["path"], f["line"])})
    loc_list = "".join("<li>%s%s</li>" % (loc(p, ln), ' <span class="dim">primary</span>' if (p, ln) == (f["path"], f["line"]) else "")
                       for p, ln in locs)
    supp = "# nexvul: ignore[%s] -- <why this is mitigated>" % f["rule"]
    if f["path"].endswith((".ts", ".js")):
        supp = "// " + supp[2:]
    dataf = esc(f["path"])
    return """
<details class="fcard fcard-%(sev)s" id="f-%(id)s" data-sev="%(sev)s" data-asi="%(asi)s" data-rule="%(rule)s" data-file="%(file)s"%(open)s>
  <summary>
    %(badge)s<span class="rid">%(rule)s</span><span class="ftitle">%(title)s</span>
    <span class="fmeta">%(tags)s<span class="conf">confidence %(conf)s</span>%(loc)s</span>
  </summary>
  <div class="fbody">
    <p class="fmsg">%(msg)s</p>
    <div class="fcols">
      <div class="fmain">%(flow)s
        <h4>Why it matters</h4><p>%(why)s</p>
        <h4>How to fix</h4><p>%(fix)s</p>
        <h4>What nexvul looked for and did not find</h4><p>%(searched)s</p>
      </div>
      <aside class="fside">
        <h4>Locations</h4><ul class="locs">%(locs)s</ul>
        <h4>Rule</h4><p><span class="rid">%(rule)s</span> %(title)s<br><span class="dim">Framework: %(fw)s</span></p>
        <h4>Not detected by this rule</h4><p class="dim-p">%(nd)s</p>
        <h4>Suppress this finding</h4>%(supp)s
        <p class="note">Add the comment on the flagged line or the line above. The reason after <code>--</code> is required in CI.</p>
        <h4>Learn the rule</h4>%(explain)s
      </aside>
    </div>
  </div>
</details>""" % dict(sev=f["sev"], id=f["id"], asi=" ".join(f["asi"]), rule=f["rule"], file=dataf,
                     open=" open" if open_ else "", badge=sev_badge(f["sev"]), title=esc(RULE_TITLE[f["rule"]]),
                     tags=asi_tags(f["asi"]), conf=f["conf"], loc=loc(f["path"], f["line"], f["col"]),
                     msg=show_ctl(f["msg"]), flow=flow, why=esc(f["why"]), fix=esc(f["fix"]),
                     searched=esc(f["searched"]), locs=loc_list, fw=esc(f["framework"]), nd=esc(f["notdetect"]),
                     supp=copy_block(supp), explain=copy_block("nexvul explain %s" % f["rule"]))


def v_findings():
    sev_btns = "".join(
        '<button type="button" class="chip chip-%s" data-sev="%s" aria-pressed="true">%s<span class="meter" '
        'aria-hidden="true">%s</span><span class="chip-n">%d</span></button>'
        % (k, k, LABEL[k].title(), METER[k], COUNTS[k]) for k in SEV_ORDER[:4])
    asis = sorted({a for f in FIND for a in f["asi"]})
    rules = sorted({f["rule"] for f in FIND})
    asi_opts = "".join('<option value="%s">%s %s</option>' % (a, a, esc(D.ASI_NAMES[a])) for a in asis)
    rule_opts = "".join('<option value="%s">%s %s</option>' % (r, r, esc(RULE_TITLE[r][:44] + ("\u2026" if len(RULE_TITLE[r]) > 44 else ""))) for r in rules)
    cards = "".join(finding_card(f, open_=(i == 0)) for i, f in enumerate(FIND))
    return """
<section class="view" id="findings" aria-labelledby="h-findings">
  %(banner)s
  <div class="view-head"><h1 id="h-findings">Findings</h1>
    <p class="sub">%(n)d findings from %(rr)d rules run, highest severity first. Select a finding to see its flow, locations and fix.</p></div>
  <form class="filters" id="filters" aria-label="Filter findings">
    <fieldset class="f-sev"><legend>Severity</legend><div class="chips">%(sev)s</div></fieldset>
    <label class="f-field"><span>ASI category</span><select id="fAsi"><option value="">All categories</option>%(asi)s</select></label>
    <label class="f-field"><span>Rule</span><select id="fRule"><option value="">All rules</option>%(rule)s</select></label>
    <label class="f-field f-file"><span>File contains</span><input id="fFile" type="search" placeholder="e.g. agent/tools" autocomplete="off" spellcheck="false"></label>
    <button type="button" class="btn btn-ghost" id="fClear">Clear filters</button>
  </form>
  <p class="count" id="fCount" aria-live="polite">Showing %(n)d of %(n)d findings</p>
  <div class="empty" id="fEmpty" hidden>
    <h3>No findings match these filters</h3>
    <p>%(n)d findings are hidden by the current filters. This is not a scan result: clear the filters to see them.</p>
    <button type="button" class="btn" id="fClear2">Clear filters</button>
  </div>
  <div class="flist" id="flist">%(cards)s</div>
  <p class="disclaimer">%(fm)s</p>
</section>""" % dict(banner=partial_banner(), n=len(FIND), rr=S["rules_run"], sev=sev_btns, asi=asi_opts,
                     rule=rule_opts, cards=cards, fm=esc(TOKENS["copy"]["finding_meaning"]))


def agent_graph():
    # node: id, label, sub, x, y, w, kind
    N = {
        "in1": ("POST /agents/run", "agent/server.py:41", 16, 40, 176, "input"),
        "in2": ("User chat message", "agent/app.py:12", 16, 130, 176, "input"),
        "sup": ("supervisor", "LangGraph node", 262, 70, 176, "agent"),
        "res": ("research_agent", "LangGraph ReAct", 262, 238, 176, "agent"),
        "bil": ("billing_agent", "OpenAI Agents SDK", 262, 392, 176, "agent"),
        "t1": ("search_web", "tool", 520, 150, 150, "tool"),
        "t2": ("fetch_url", "tool", 520, 210, 150, "tool"),
        "t3": ("index_docs", "tool", 520, 270, 150, "tool"),
        "t4": ("run_shell", "tool", 520, 330, 150, "tool"),
        "t5": ("refund_order", "tool", 520, 392, 150, "tool"),
        "s1": ('MCP server "search"', "http:// remote host", 806, 150, 218, "sink"),
        "s2": ("Network: any host", "requests.get(url)", 806, 210, 218, "sink"),
        "s3": ("vector_store.add_documents", "LangChain vector store", 806, 270, 218, "sink"),
        "s4": ("subprocess.run(shell=True)", "shell execution", 806, 330, 218, "sink"),
        "s5": ("stripe.Refund.create", "financial action", 806, 392, 218, "sink"),
    }
    H = 44
    E = [("in1", "sup", ""), ("in2", "sup", ""), ("sup", "res", "delegates"), ("sup", "bil", "delegates"),
         ("res", "t1", ""), ("res", "t2", ""), ("res", "t3", ""), ("res", "t4", ""), ("bil", "t5", ""),
         ("t1", "s1", ""), ("t2", "s2", ""), ("t3", "s3", ""), ("t4", "s4", ""), ("t5", "s5", "")]
    out = ['<svg class="agraph" viewBox="0 0 1040 470" role="img" aria-labelledby="ag-t ag-d">'
           '<title id="ag-t">Agent and tool graph for my-agent-project</title>'
           '<desc id="ag-d">Inputs reach the supervisor, which delegates to research_agent and billing_agent. '
           'research_agent has four tools; billing_agent has refund_order. The table below lists the same '
           'information.</desc>'
           '<defs><marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" '
           'orient="auto-start-reverse"><path d="M0 0 8 4 0 8z" class="arrowhead"/></marker></defs>']
    for col, x, label in [(0, 16, "INPUTS"), (1, 262, "AGENTS"), (2, 520, "TOOLS"), (3, 806, "SENSITIVE SINKS")]:
        out.append('<text class="g-col" x="%d" y="18">%s</text>' % (x, label))

    def right(n):
        _, _, x, y, w, _ = N[n]
        return x + w, y + H / 2

    def left(n):
        _, _, x, y, w, _ = N[n]
        return x, y + H / 2

    for a, b, lab in E:
        if N[a][2] == N[b][2] and not (a == "sup" and b in ("res", "bil")):
            continue
        x1, y1 = right(a)
        x2, y2 = left(b)
        if a == "sup" and b in ("res", "bil"):
            # vertical delegation inside the agents column
            _, _, x, y, w, _ = N[a]
            _, _, bx, by, bw, _ = N[b]
            if b == "res":
                out.append('<path class="g-edge" d="M%d %d L%d %d" marker-end="url(#arr)"/>' % (x + 60, y + H, bx + 60, by - 2))
            else:
                out.append('<path class="g-edge" d="M%d %d L%d %d L%d %d L%d %d" marker-end="url(#arr)"/>' % (x, y + H / 2, x - 18, y + H / 2, x - 18, by + H / 2, bx - 2, by + H / 2))
            continue
        cx = (x2 - x1) * 0.5
        out.append('<path class="g-edge" d="M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f" marker-end="url(#arr)"/>'
                   % (x1, y1, x1 + cx, y1, x2 - cx, y2, x2 - 2, y2))
    # cycle research_agent -> supervisor (NEX011)
    out.append('<path class="g-edge g-cycle" d="M%d %d L%d %d" marker-end="url(#arr)"/>' % (262 + 120, 238, 262 + 120, 70 + H + 2))
    out.append('<text class="g-elabel" x="%d" y="%d">delegates</text>' % (262 + 66, 168))
    out.append('<text class="g-elabel" x="%d" y="%d">routes back</text>' % (262 + 126, 196))
    for n, (lab, sub, x, y, w, kind) in N.items():
        rx = 22 if kind == "tool" else (4 if kind == "sink" else 8)
        out.append('<g class="g-node g-%s"><rect x="%d" y="%d" width="%d" height="%d" rx="%d"/>'
                   '<text class="g-lab" x="%d" y="%d">%s</text><text class="g-sub" x="%d" y="%d">%s</text></g>'
                   % (kind, x, y, w, H, rx, x + 12, y + 19, esc(lab), x + 12, y + 35, esc(sub)))
    # finding markers: (x, y, sev, text)
    M = [(690, 136, "high", "NEX007 HIGH"), (690, 256, "high", "NEX002 HIGH"),
         (678, 370, "critical", "NEX018 CRITICAL"), (270, 292, "high", "NEX020 HIGH"),
         (396, 150, "medium", "NEX011 MEDIUM"), (452, 60, "medium", "NEX014 MEDIUM"),
         (16, 94, "info", "NEX006 suppressed"), (690, 196, "low", "NEX015 LOW")]
    for x, y, sev, t in M:
        w = 16 + len(t) * 7.0
        out.append('<g class="g-mark g-m-%s"><rect x="%.0f" y="%d" width="%.0f" height="20" rx="10"/>'
                   '<text x="%.0f" y="%d">%s</text></g>' % (sev, x, y, w, x + 8, y + 14, esc(t)))
    out.append("</svg>")
    return "".join(out)


def v_agents():
    fw = "".join(
        '<div class="fw"><div class="fw-head"><strong>%s</strong><span class="tag">%s</span></div>'
        '<p class="dim-p">%s</p><p class="fw-meta">%s &middot; <strong>%d</strong> rules attached</p></div>'
        % (esc(n), esc(v), esc(how), "<strong>%d</strong> file%s" % (files, "" if files == 1 else "s"), rules) for n, v, files, how, rules in D.FRAMEWORKS)
    rows = "".join(
        "<tr><th scope=\"row\"><code>%s</code><br><span class=\"dim\">%s</span></th><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (esc(a), esc(k), esc(t), esc(s), esc(c),
           " ".join('<a href="#findings/%s">%s</a>' % (fid, next(f["rule"] for f in FIND if f["id"] == fid)) for fid in fids))
        for a, k, t, s, c, fids in D.AGENTS_TABLE)
    return """
<section class="view" id="agents" aria-labelledby="h-agents">
  <div class="view-head"><h1 id="h-agents">Frameworks and agent map</h1>
    <p class="sub">What nexvul recognised in the scanned code: frameworks, agents, their tools, and the sensitive calls those tools can reach.</p></div>
  <div class="fw-grid">%(fw)s</div>
  <p class="note">Not recognised: %(nr)s. Rules that depend on a framework attach only to the frameworks above.</p>
  <section class="panel" aria-labelledby="h-graph"><div class="panel-head"><h2 id="h-graph">Agent and tool graph</h2>
    <span class="dim">Built from static analysis; runtime wiring outside this repository is not shown</span></div>
    <div class="graph-wrap">%(graph)s</div>
    <ul class="g-legend">
      <li><span class="lg lg-input" aria-hidden="true"></span>Input (where outside data enters)</li>
      <li><span class="lg lg-agent" aria-hidden="true"></span>Agent</li>
      <li><span class="lg lg-tool" aria-hidden="true"></span>Tool</li>
      <li><span class="lg lg-sink" aria-hidden="true"></span>Sensitive sink</li>
      <li><span class="lg lg-cycle" aria-hidden="true"></span>Cycle (dashed)</li>
      <li>Pills name the rule and severity in words</li>
    </ul>
  </section>
  <section class="panel" aria-labelledby="h-atable"><div class="panel-head"><h2 id="h-atable">Agents, tools and controls</h2><span class="dim">Same information as the graph, as a table</span></div>
    <div class="tscroll"><table class="tbl">
      <thead><tr><th scope="col">Agent</th><th scope="col">Tools</th><th scope="col">Reachable sensitive sinks</th><th scope="col">Controls found</th><th scope="col">Findings</th></tr></thead>
      <tbody>%(rows)s</tbody></table></div>
    <p class="note">"none found" means none in the scanned code. Gateways, IAM and sandboxes outside this repository are not visible to nexvul.</p>
  </section>
</section>""" % dict(fw=fw, nr=esc(D.NOT_RECOGNISED), graph=agent_graph(), rows=rows)


def v_rules():
    counts = {}
    for f in FIND:
        counts[f["rule"]] = counts.get(f["rule"], 0) + 1
    rows = []
    for rid, title, asi, cls, sev, prov in D.RULES:
        st, src = D.RULE_STATE.get(rid, ("on", "default"))
        n = counts.get(rid, 0)
        rows.append('<tr data-asi="%s"><th scope="row"><span class="rid">%s</span></th><td>%s</td><td>%s</td><td>%s</td>'
                    '<td>%s</td><td><span class="state state-%s">%s</span><br><span class="dim">%s</span></td><td class="num">%s</td>'
                    '<td><span class="ready">design only</span></td></tr>'
                    % (" ".join(asi), rid, esc(title), asi_tags(asi, prov), esc(cls), sev_badge(sev), st,
                       "runs" if st == "on" else "off", esc(src),
                       '<a href="#findings/rule=%s">%d</a>' % (rid, n) if n else '<span class="dim">0</span>'))
    asis = sorted({a for r in D.RULES for a in r[2]})
    opts = "".join('<option value="%s">%s %s</option>' % (a, a, esc(D.ASI_NAMES[a])) for a in asis)
    return """
<section class="view" id="rules" aria-labelledby="h-rules">
  <div class="view-head"><h1 id="h-rules">Rules</h1>
    <p class="sub">%(rr)d of %(rt)d rules ran in this scan. Rule IDs and titles are a public contract; IDs are never reused.</p></div>
  <div class="callout">Every rule below is <strong>design only</strong> in this mock-up: none is implemented, tested or benchmarked yet. ASI labels marked <span class="tag tag-prov">provisional</span> are pending the mapping decision (OD-02).</div>
  <div class="filters filters-inline"><label class="f-field"><span>ASI category</span><select id="rAsi"><option value="">All categories</option>%(opts)s</select></label>
    <p class="count" id="rCount" aria-live="polite">Showing 25 rules</p></div>
  <div class="tscroll"><table class="tbl tbl-rules" id="rtable">
    <thead><tr><th scope="col">ID</th><th scope="col">Title</th><th scope="col">OWASP ASI</th><th scope="col">Class</th><th scope="col">Default severity</th><th scope="col">This run</th><th scope="col">Findings</th><th scope="col">Readiness</th></tr></thead>
    <tbody>%(rows)s</tbody></table></div>
  <p class="note">Full text of a rule, with examples and what it does not detect: <code>nexvul explain NEX018</code> or <code>docs/rules/NEX018.md</code>.</p>
</section>""" % dict(rr=S["rules_run"], rt=S["rules_total"], opts=opts, rows="".join(rows))


SUPP_STATUS = {
    "applied": ("applied", "Applied", ""),
    "applied-nojust": ("warn", "Applied locally, no justification",
                       "In CI this suppression is NOT applied and the finding stays active."),
    "rejected-hidden": ("rejected", "Rejected: hidden character",
                        "Contains U+202E RIGHT-TO-LEFT OVERRIDE. The finding stays active."),
    "stale": ("stale", "Stale: matched no finding", "Remove it, or check whether the code moved."),
}


def v_suppressions():
    rows = []
    for s in D.SUPPRESSIONS:
        cls, word, expl = SUPP_STATUS[s["status"]]
        j = ('<q class="just">%s</q>' % show_ctl(trunc(s["just"], TOKENS["truncation"]["justification_display_max"]))
             if s["just"] else '<span class="dim">(no justification)</span>')
        new = '<span class="flag-new">Added on this branch</span>' if s["new"] else ""
        rows.append('<tr><th scope="row"><span class="rid">%s</span></th><td>%s</td><td>%s</td><td>%s %s</td>'
                    '<td><span class="sstate sstate-%s">%s</span>%s</td></tr>'
                    % (s["rule"], loc(s["path"], s["line"]), esc(s["kind"]), j, new, cls, esc(word),
                       '<br><span class="dim">%s</span>' % esc(expl) if expl else ""))
    return """
<section class="view" id="suppressions" aria-labelledby="h-supp">
  <div class="view-head"><h1 id="h-supp">Suppressions</h1>
    <p class="sub">A suppression is a claim made in the scanned code by the person whose code was flagged. nexvul never hides one: every suppression is counted and shown here.</p></div>
  <div class="tiles tiles-4">
    <div class="tile"><span class="tile-label">Applied</span><span class="tile-num">%(applied)d</span><span class="tile-foot">1 without a justification</span></div>
    <div class="tile"><span class="tile-label">Added on this branch</span><span class="tile-num">3</span><span class="tile-foot">vs <code>%(base)s</code></span></div>
    <div class="tile"><span class="tile-label">Rejected</span><span class="tile-num">1</span><span class="tile-foot">finding stays active</span></div>
    <div class="tile"><span class="tile-label">Stale</span><span class="tile-num">1</span><span class="tile-foot">matched nothing</span></div>
  </div>
  <div class="tscroll"><table class="tbl">
    <thead><tr><th scope="col">Rule</th><th scope="col">Location</th><th scope="col">Kind</th><th scope="col">Justification (from the scanned code)</th><th scope="col">Status</th></tr></thead>
    <tbody>%(rows)s</tbody></table></div>
  <p class="note">Justifications are untrusted text from the repository. They are shown escaped and truncated to 120 characters; hidden characters are shown as their code point.</p>
  <section class="panel" aria-labelledby="h-weak"><div class="panel-head"><h2 id="h-weak">Protections weakened by repository configuration</h2></div>
    <ul class="weak">
      <li><code>rules.disabled: [NEX022]</code> &mdash; applied (local run, <code>.nexvul.yml:9</code>). <strong>In CI mode: NOT APPLIED</strong> unless the base branch has the same value.</li>
      <li><code>exclude: ["gen/**", "vendor/**"]</code> &mdash; applied; 18 files excluded and counted. <strong>In CI mode:</strong> the base-branch value is used.</li>
    </ul></section>
  <section class="panel" aria-labelledby="h-syntax"><div class="panel-head"><h2 id="h-syntax">Suppression syntax</h2></div>
    %(py)s %(ts)s
    <p class="note">Name the rule; a blanket <code>ignore</code> is rejected. Several rules: <code>ignore[NEX016,NEX017]</code>. Applies to the same line or the next non-comment line.</p></section>
</section>""" % dict(applied=APPLIED_SUPP, base=esc(S["base"]), rows="".join(rows),
                     py=copy_block("# nexvul: ignore[NEX006] -- auth enforced by the API gateway (infra/gateway.tf)"),
                     ts=copy_block("// nexvul: ignore[NEX016] -- tool runs only in the sandbox account"))


def v_history():
    total = sum(t for _, t in D.PHASES)
    x, bars = 0.0, []
    for i, (name, t) in enumerate(D.PHASES):
        w = 100.0 * t / total
        bars.append('<rect class="ph ph-%d" x="%.2f" y="0" width="%.2f" height="12"/>' % (i, x, max(w - 0.4, 0.4)))
        x += w
    plist = "".join('<li><span class="sw ph-sw-%d" aria-hidden="true"></span>%s <strong>%.1f s</strong></li>' % (i, n, t)
                    for i, (n, t) in enumerate(D.PHASES))
    reasons = "".join(
        '<tr><td>%s</td><td class="num">%d</td><td>%s</td></tr>'
        % (esc(r), n, ", ".join(code(p, "loc") for p in ex)) for r, n, ex in D.PARTIAL["reasons"])
    prov = [
        ("Status", '<span class="only-complete">COMPLETE</span><span class="only-partial"><strong>PARTIAL</strong></span>'),
        ("Files discovered", "%d (%s)" % (S["files_discovered"], S["files_by_lang"])),
        ("Files analysed", '<span class="only-complete">%d</span><span class="only-partial">%d (%d not analysed)</span>'
         % (S["files_analysed"], D.PARTIAL["analysed"], D.PARTIAL["not_analysed"])),
        ("Excluded by config", "%d files (<code>gen/**</code>, <code>vendor/**</code>); counted, not analysed" % S["excluded"]),
        ("Rules run", "%d of %d (2 experimental off, 1 disabled by .nexvul.yml)" % (S["rules_run"], S["rules_total"])),
        ("Limits hit", "none"), ("Budgets exhausted", "none"), ("Findings truncated", "no"),
        ("Analysis-limited", "%d dynamic imports not followed (agent/plugins.py)" % S["dynamic_not_followed"]),
        ("Suppressions", "%d applied, 1 rejected, 1 stale" % APPLIED_SUPP),
        ("Config sources", "<code>.nexvul.yml</code> (local file, sha256 4be1…), CLI flags, defaults"),
        ("Plugins", "none loaded"),
        ("nexvul", "%s &middot; rules %s (%s) &middot; Python %s" % (S["version"], S["rules_pack"], esc(S["rules_hash"]), S["python"])),
        ("Command", "<code>%s</code>" % esc(S["command"])),
    ]
    prov_rows = "".join('<tr><th scope="row">%s</th><td>%s</td></tr>' % (k, v) for k, v in prov)
    return """
<section class="view" id="history" aria-labelledby="h-hist">
  %(banner)s
  <div class="view-head"><h1 id="h-hist">Scan history</h1>
    <p class="sub">This report holds one run: the scan that wrote this file. nexvul keeps no history between runs and sends nothing anywhere.</p></div>
  <section class="panel run" aria-labelledby="h-run"><div class="panel-head"><h2 id="h-run">This run</h2><span class="dim">%(started)s &rarr; %(ended)s &middot; %(dur)s</span></div>
    <dl class="run-meta">
      <div><dt>Result</dt><dd class="only-complete">%(at)d at or above fail-on &middot; exit code 1</dd><dd class="only-partial">Scan incomplete &middot; exit code 3</dd></div>
      <div><dt>Mode</dt><dd>local (not CI)</dd></div>
      <div><dt>Branch</dt><dd><code>%(branch)s</code> at <code>%(commit)s</code></dd></div>
      <div><dt>Compared with</dt><dd>nothing: no earlier run is stored</dd></div>
    </dl>
    <h3 class="h3">Time by phase</h3>
    <div class="dist"><svg viewBox="0 0 100 12" preserveAspectRatio="none" role="img" aria-label="Time by phase: %(alt)s">%(bars)s</svg><ul class="legend">%(plist)s</ul></div>
  </section>
  <section class="panel only-partial" aria-labelledby="h-na"><div class="panel-head"><h2 id="h-na">Not analysed (%(na)d files)</h2></div>
    <table class="tbl"><thead><tr><th scope="col">Reason</th><th scope="col">Files</th><th scope="col">Paths (first 50)</th></tr></thead><tbody>%(reasons)s</tbody></table>
    <p class="note">Code in these files was not checked. Fix the parse errors, or exclude generated files in <code>.nexvul.yml</code>; exclusions are counted in every report.</p>
  </section>
  <section class="panel" aria-labelledby="h-prov"><div class="panel-head"><h2 id="h-prov">Completeness and provenance</h2></div>
    <table class="tbl tbl-kv"><tbody>%(prov)s</tbody></table></section>
  <section class="panel" aria-labelledby="h-cmp"><div class="panel-head"><h2 id="h-cmp">Compare runs yourself</h2></div>
    <p>Keep a JSON result per run and compare them with your own tools. Reports stay on your machine.</p>
    %(cmd)s</section>
</section>""" % dict(banner=partial_banner(), started=esc(S["started"]), ended=esc(S["ended"]), dur=S["duration"],
                     at=AT_OR_ABOVE, branch=esc(S["branch"]), commit=esc(S["commit"]),
                     alt=", ".join("%s %.1f s" % p for p in D.PHASES), bars="".join(bars), plist=plist,
                     na=D.PARTIAL["not_analysed"], reasons=reasons, prov=prov_rows,
                     cmd=copy_block("nexvul scan . --format json --output runs/2026-10-08.json"))


def v_settings():
    rows = []
    for k, v, src, weak, ci in D.CONFIG:
        srccls = "cli" if src.startswith("CLI") else ("file" if ".nexvul.yml" in src else "default")
        rows.append('<tr><th scope="row"><code>%s</code></th><td><code>%s</code></td><td><span class="src src-%s">%s</span></td>'
                    '<td>%s</td><td>%s</td></tr>'
                    % (esc(k), esc(v), srccls, esc(src), '<span class="weakv">%s</span>' % esc(weak) if weak else
                       '<span class="dim">no</span>', ('<strong>%s</strong>' % esc(ci)) if "NOT" in ci or "forced" in ci else esc(ci)))
    chips = []
    for rid, title, *_ in D.RULES:
        st, src = D.RULE_STATE.get(rid, ("on", "default"))
        chips.append('<li class="rchip rchip-%s" title="%s"><span class="rid">%s</span><span class="state state-%s">%s</span></li>'
                     % (st, esc(title + " - " + src), rid, st, "on" if st == "on" else "off"))
    return """
<section class="view" id="settings" aria-labelledby="h-set">
  <div class="view-head"><h1 id="h-set">Settings</h1>
    <p class="sub">The configuration this scan used, and where each value came from. Read-only: this report never writes to <code>.nexvul.yml</code> or to your source files.</p></div>
  <div class="callout">To change a setting, edit <code>.nexvul.yml</code> or pass a flag, then run the scan again. Copy the lines you need from <a href="#change">Change a setting</a>.</div>
  <section class="panel" aria-labelledby="h-eff"><div class="panel-head"><h2 id="h-eff">Effective configuration</h2><span class="dim">Precedence: CLI flag &gt; .nexvul.yml &gt; default</span></div>
    <div class="tscroll"><table class="tbl tbl-cfg"><thead><tr><th scope="col">Key</th><th scope="col">Value used</th><th scope="col">Source</th><th scope="col">Weakens the scan</th><th scope="col">In CI mode</th></tr></thead>
    <tbody>%(rows)s</tbody></table></div></section>
  <section class="panel panel-warn" aria-labelledby="h-ci"><div class="panel-head"><h2 id="h-ci">Not applied in CI mode</h2></div>
    <p>In CI, settings that weaken the scan are read only from the base branch. If this branch were scanned in CI, these values from the working copy would <strong>not</strong> be applied:</p>
    <ul class="weak"><li><code>rules.disabled: [NEX022]</code> &mdash; NEX022 would run.</li>
      <li><code>exclude: ["gen/**", "vendor/**"]</code> &mdash; the base branch's <code>exclude</code> would be used.</li>
      <li><code>suppressions.require_justification</code> &mdash; forced to <code>true</code>; the suppression at <code>agent/tools.py:88</code> would not apply.</li></ul></section>
  <section class="panel" aria-labelledby="h-rs"><div class="panel-head"><h2 id="h-rs">Rules enabled in this scan</h2><span class="dim">%(rr)d on &middot; %(off)d off</span></div>
    <ul class="rchips">%(chips)s</ul>
    <p class="note">Off: NEX004 and NEX023 (experimental, off by default); NEX022 (<code>rules.disabled</code> in <code>.nexvul.yml:9</code>).</p></section>
  <section class="panel" aria-labelledby="h-disp"><div class="panel-head"><h2 id="h-disp">Display preferences</h2><span class="dim">Saved in this browser only</span></div>
    <form class="prefs" id="prefs">
      <fieldset><legend>Theme</legend>
        <label class="radio"><input type="radio" name="theme" value="system" checked> Match system</label>
        <label class="radio"><input type="radio" name="theme" value="light"> Light</label>
        <label class="radio"><input type="radio" name="theme" value="dark"> Dark</label></fieldset>
      <fieldset><legend>Density</legend>
        <label class="radio"><input type="radio" name="density" value="comfortable" checked> Comfortable</label>
        <label class="radio"><input type="radio" name="density" value="compact"> Compact</label></fieldset>
      <fieldset><legend>Findings</legend>
        <label class="check"><input type="checkbox" name="show_low_info" checked> Show low and info findings when the Findings view opens</label>
        <label class="check"><input type="checkbox" name="wrap_code"> Wrap long code lines</label></fieldset>
    </form>
    <p class="note" id="prefStatus" aria-live="polite">Preferences are stored in this browser's local storage under <code>%(key)s</code>. They never change the scan, the config file or the result.</p></section>
  <section class="panel" id="change" aria-labelledby="h-chg"><div class="panel-head"><h2 id="h-chg">Change a setting</h2></div>
    <p class="lbl">Fail on medium for one run</p>%(c1)s
    <p class="lbl">Re-enable NEX022 (remove it from <code>.nexvul.yml</code>)</p>%(c2)s
    <p class="lbl">Turn on an experimental rule</p>%(c3)s
    <p class="lbl">See every effective value and its source in the terminal</p>%(c4)s
  </section>
</section>""" % dict(rows="".join(rows), rr=S["rules_run"], off=S["rules_total"] - S["rules_run"], chips="".join(chips),
                     key=esc(TOKENS["storage"]["report_prefs_key"]),
                     c1=copy_block("nexvul scan . --fail-on medium"),
                     c2=copy_block("rules:\n  disabled: []"),
                     c3=copy_block("rules:\n  enabled: [ASI06, ASI07, ASI08, ASI09, ASI10, NEX004]"),
                     c4=copy_block("nexvul scan . --verbose"))


def v_help():
    sev_rows = "".join('<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        sev_badge(k), esc(TOKENS["severity"][k]["security_severity"] or "not uploaded"),
        "yes" if TOKENS["severity"][k]["fails_at_default_threshold"] else "no") for k in SEV_ORDER)
    return """
<section class="view" id="help" aria-labelledby="h-help">
  <div class="view-head"><h1 id="h-help">Help and docs</h1>
    <p class="sub">How to read this report. Everything here is also in the docs folder of the nexvul repository.</p></div>
  <div class="grid-2">
    <section class="panel"><div class="panel-head"><h2>Reading a finding</h2></div>
      <ol class="plain"><li><strong>Severity</strong> is a word and a meter, never colour alone.</li>
        <li><strong>Rule ID</strong> (<code>NEX018</code>) and title say which pattern matched.</li>
        <li><strong>Flow</strong> lists numbered steps from <em>source</em> (where outside data enters) to <em>sink</em> (where it has an effect).</li>
        <li><strong>Confidence</strong> is high, medium or low: how sure nexvul is that the pattern is really there.</li>
        <li><strong>How to fix</strong> names the control to add.</li></ol>
      <p class="note">%(fm)s</p></section>
    <section class="panel"><div class="panel-head"><h2>Scan status</h2></div>
      <table class="tbl"><tbody>
        <tr><th scope="row">COMPLETE</th><td>Every discovered, non-excluded file was parsed and analysed within limits.</td></tr>
        <tr><th scope="row">PARTIAL SCAN</th><td>Something was not analysed. The result is not a clean bill of health.</td></tr>
        <tr><th scope="row">SCAN FAILED</th><td>No usable result. The report still explains why.</td></tr></tbody></table></section>
    <section class="panel"><div class="panel-head"><h2>Severity</h2></div>
      <table class="tbl"><thead><tr><th scope="col">Label</th><th scope="col">GitHub security-severity</th><th scope="col">Fails at default fail-on</th></tr></thead><tbody>%(sev)s</tbody></table></section>
    <section class="panel"><div class="panel-head"><h2>Exit codes</h2></div>
      <table class="tbl"><tbody>
        <tr><th scope="row">0</th><td>Scan complete, no findings at or above fail-on</td></tr>
        <tr><th scope="row">1</th><td>Scan complete, findings at or above fail-on</td></tr>
        <tr><th scope="row">2</th><td>Usage or configuration error; nothing was scanned</td></tr>
        <tr><th scope="row">3</th><td>Scan incomplete (files not analysed, limits hit, or nothing to analyse)</td></tr>
        <tr><th scope="row">4</th><td>Internal error in nexvul</td></tr></tbody></table></section>
    <section class="panel"><div class="panel-head"><h2>Commands</h2></div>
      %(c1)s %(c2)s %(c3)s %(c4)s</section>
    <section class="panel"><div class="panel-head"><h2>Privacy and this file</h2></div>
      <ul class="plain"><li>This report is a single file on your disk. It makes no network requests and loads no fonts, images or scripts from elsewhere.</li>
        <li>There is no account, sign-in or server. Nothing to sign up for or log out of.</li>
        <li>Display preferences stay in this browser's local storage. Clearing site data removes them.</li>
        <li>Paths, code and justifications come from the scanned repository and are shown as escaped text.</li></ul>
      <p class="note">Docs: <code>docs/rules/NEX0nn.md</code> for each rule, <code>README.md</code> for CI and pre-commit setup.</p></section>
  </div>
  <p class="disclaimer">%(disc)s</p>
</section>""" % dict(fm=esc(TOKENS["copy"]["finding_meaning"]), sev=sev_rows,
                     c1=copy_block("nexvul explain NEX018"), c2=copy_block("nexvul rules --asi ASI07"),
                     c3=copy_block("nexvul doctor"), c4=copy_block("nexvul scan . --format sarif --output nexvul.sarif"),
                     disc=esc(TOKENS["copy"]["disclaimer"]))


# ------------------------------------------------------------------ CSS / JS

CSS = r"""
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.5 var(--body);font-variant-numeric:tabular-nums}
a{color:var(--accent-text);text-underline-offset:2px}
code,pre,.mono{font-family:var(--mono);font-size:12px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
h1,h2,h3,h4{margin:0;line-height:1.25}
.dim,.dim-p{color:var(--dim)} .note{color:var(--muted);font-size:12px;margin:8px 0 0}
.mockband{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:center;background:var(--mock-band);color:var(--mock-band-text);font-size:12px;padding:6px 16px;border-bottom:1px solid var(--border)}
.mockband strong{letter-spacing:.06em;text-transform:uppercase}
.mockband .seg-ctl{display:inline-flex;gap:4px;align-items:center}
.mockband button{font:inherit;color:inherit;background:transparent;border:1px solid currentColor;border-radius:4px;padding:2px 8px;min-height:28px;cursor:pointer}
.mockband button[aria-pressed="true"]{background:var(--mock-band-text);color:var(--mock-band)}
.shell{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
.nav{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;background:var(--nav);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:12px 10px}
.nav-head{display:flex;align-items:center;gap:8px;padding:6px 8px 14px;color:var(--text)}
.wordmark{font-family:var(--mono);font-weight:700;letter-spacing:-.02em;font-size:17px}
.nav-close{margin-left:auto;display:none}
.nav-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);padding:10px 10px 4px}
.nav ul{list-style:none;margin:0;padding:0}
.nav-link{display:flex;align-items:center;gap:10px;min-height:40px;padding:8px 10px;border-radius:8px;color:var(--muted);text-decoration:none;font-weight:500}
.nav-link:hover{background:var(--card-hover);color:var(--text)}
.nav-link[aria-current="page"]{background:var(--accent-tint);color:var(--accent-text);font-weight:600}
.nav-text{flex:1}
.nav-count{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:10px;padding:0 7px;line-height:18px;background:var(--card)}
.nav-foot{margin-top:auto;padding:12px 10px 4px;font-size:12px;color:var(--muted);border-top:1px solid var(--border-subtle)}
.nav-foot p{margin:0 0 6px}
.maincol{min-width:0}
.topbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:16px;min-height:56px;padding:8px 24px;background:var(--raised);border-bottom:1px solid var(--border)}
.menu-btn{display:none}
.btn-icon{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer}
.btn-icon.menu-btn,.btn-icon.nav-close{display:none}
.target{display:flex;flex-direction:column;min-width:0}
.target-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
.target-val{display:flex;flex-wrap:wrap;gap:4px 8px;align-items:baseline;color:var(--text)}
.target-val code{font-size:13px;font-weight:600}
.meta{color:var(--muted);font-size:12px} .meta code{font-weight:500;font-size:12px}
.sep{color:var(--dim)}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.status-pill{display:inline-flex;align-items:center;gap:8px;min-height:32px;padding:4px 12px;border-radius:16px;text-decoration:none;font-size:12px;border:1px solid var(--border-strong);color:var(--text);background:var(--card)}
.status-word{font-weight:700;letter-spacing:.06em}
.status-partial{background:repeating-linear-gradient(45deg,var(--partial-fill) 0 8px,var(--hatch) 8px 10px),var(--partial-fill);background-blend-mode:normal;color:var(--partial-on);border-color:var(--partial-fill)}
.status-partial .status-detail{color:var(--partial-on)}
.status-detail{color:var(--muted)}
.exit-chip{font-family:var(--mono);font-size:12px;border:1px solid var(--border);border-radius:4px;padding:3px 8px;color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:6px;min-height:36px;padding:6px 12px;border-radius:8px;border:1px solid var(--border-strong);background:var(--card);color:var(--text);font:inherit;font-weight:500;cursor:pointer}
.btn:hover{background:var(--card-hover)}
.btn-ghost{border-color:var(--border)}
.btn-sm{min-height:30px;padding:3px 10px;font-size:12px}
.content{max-width:1120px;padding:24px 24px 48px}
.view{margin-bottom:56px}
html.js .view{display:none;margin-bottom:0}
html.js .view.active{display:block}
.view-head{margin:4px 0 16px}
.view-head h1{font-size:24px;font-weight:650;letter-spacing:-.01em}
.sub{color:var(--muted);margin:6px 0 0;max-width:80ch}
.only-partial{display:none!important}
html[data-scan="partial"] .only-partial{display:revert!important}
html[data-scan="partial"] .status-pill.only-partial{display:inline-flex!important}
html[data-scan="partial"] .only-complete{display:none!important}
.banner-partial{margin:0 0 16px;padding:12px 16px;border-radius:8px;color:var(--partial-on);background:repeating-linear-gradient(45deg,var(--partial-fill) 0 10px,var(--hatch) 10px 13px),var(--partial-fill);font-weight:500}
.banner-partial a{color:var(--partial-on);font-weight:700}
.result-line{font-size:15px;margin:0 0 16px}
.tiles{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:10px}
.tiles-4{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:16px}
.tile{display:flex;flex-direction:column;gap:2px;min-height:96px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;background:var(--card);color:var(--text);text-decoration:none;box-shadow:0 1px 2px var(--shadow)}
a.tile:hover{border-color:var(--border-strong);background:var(--card-hover)}
.tile-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600;display:flex;gap:6px;align-items:center}
.tile-num{font-size:28px;font-weight:650;line-height:1.15;margin-top:4px}
.tile-status .tile-num{font-size:20px;margin-top:10px}
.tile-foot{font-size:12px;color:var(--muted);margin-top:auto}
.tile-sev{border-top-width:3px}
.tile-critical{border-top-color:var(--sev-critical)} .tile-critical .tile-label{color:var(--sev-critical)}
.tile-high{border-top-color:var(--sev-high)} .tile-high .tile-label{color:var(--sev-high)}
.tile-medium{border-top-color:var(--sev-medium)} .tile-medium .tile-label{color:var(--sev-medium)}
.tile-low{border-top-color:var(--sev-low)} .tile-low .tile-label{color:var(--sev-low)}
.meter{font-family:var(--mono);letter-spacing:-.5px;font-size:10px}
.dist{margin:14px 0 4px}
.dist svg{display:block;width:100%;height:10px;border-radius:5px;overflow:hidden;background:var(--inset)}
.seg-critical,.sw-critical{fill:var(--sev-critical);background:var(--sev-critical)}
.seg-high,.sw-high{fill:var(--sev-high);background:var(--sev-high)}
.seg-medium,.sw-medium{fill:var(--sev-medium);background:var(--sev-medium)}
.seg-low,.sw-low{fill:var(--sev-low);background:var(--sev-low)}
.legend{list-style:none;display:flex;flex-wrap:wrap;gap:4px 16px;margin:8px 0 0;padding:0;font-size:12px;color:var(--muted)}
.legend li{display:flex;align-items:center;gap:6px}
.sw{display:inline-block;width:10px;height:10px;border-radius:2px}
.strip{display:flex;flex-wrap:wrap;align-items:center;gap:6px 16px;margin:16px 0 20px;padding:10px 14px;border:1px solid var(--border);border-left:3px solid var(--text);border-radius:8px;background:var(--inset)}
html[data-scan="partial"] .strip{border-left-color:var(--partial-fill)}
.strip-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;font-weight:700}
.strip-items{list-style:none;display:flex;flex-wrap:wrap;gap:4px 14px;margin:0;padding:0;font-size:13px;color:var(--muted)}
.strip-items strong{color:var(--text)}
.strip-warn strong{text-decoration:underline;text-decoration-color:var(--partial-fill);text-decoration-thickness:3px}
.strip-link{margin-left:auto;font-size:13px}
.grid-2{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:16px;align-items:start}
.stack{display:grid;gap:16px}
.panel{border:1px solid var(--border);border-radius:10px;background:var(--card);padding:14px 16px;margin-bottom:16px;box-shadow:0 1px 2px var(--shadow)}
.grid-2 .panel,.stack .panel{margin-bottom:0}
.panel-warn{border-left:3px solid var(--partial-fill)}
.panel-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px;margin-bottom:10px}
.panel-head h2{font-size:15px;font-weight:650}
.panel-head a,.panel-head .dim{margin-left:auto;font-size:12px}
.h3{font-size:13px;margin:16px 0 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-size:11px}
.toplist{list-style:none;margin:0;padding:0}
.toprow{display:grid;grid-template-columns:auto auto minmax(0,1fr);grid-template-areas:"b r t" ". . l";gap:2px 10px;align-items:center;padding:10px 6px;border-top:1px solid var(--border-subtle);color:var(--text);text-decoration:none}
.toplist li:first-child .toprow{border-top:0}
.toprow:hover{background:var(--card-hover)}
.toprow .sev{grid-area:b}.toprow .rid{grid-area:r}.toprow .ttl{grid-area:t;font-weight:500}.toprow .loc{grid-area:l;grid-column:3}
.sev{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.06em;border:1px solid;white-space:nowrap}
.sev-critical{background:var(--failed-fill);color:var(--failed-on);border-color:var(--failed-fill)}
.sev-high{color:var(--sev-high);background:var(--sev-high-tint);border-color:var(--sev-high-border)}
.sev-medium{color:var(--sev-medium);background:var(--sev-medium-tint);border-color:var(--sev-medium-border)}
.sev-low{color:var(--sev-low);background:var(--sev-low-tint);border-color:var(--sev-low-border)}
.sev-info{color:var(--sev-info);background:var(--sev-info-tint);border-color:var(--sev-info-border)}
.rid{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--accent-text)}
.loc{color:var(--muted);word-break:break-all}
.tag{display:inline-block;font-size:11px;border:1px solid var(--border);border-radius:4px;padding:0 6px;color:var(--muted);background:var(--inset);margin-right:4px;line-height:18px}
.tag-prov{border-style:dashed}
.asi-list{list-style:none;margin:0;padding:0}
.asi-list li{display:grid;grid-template-columns:52px minmax(0,1fr) 80px 20px;gap:8px;align-items:center;padding:5px 0;font-size:13px}
.asi-id{font-family:var(--mono);font-size:12px;font-weight:600}
.asi-name{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.asi-bar svg{display:block;width:100%;height:8px}
.asi-bar rect{fill:var(--accent)}
.asi-n{text-align:right;font-weight:600}
.kv{margin:0}
.disclaimer{margin:24px 0 0;padding:12px 14px;border:1px solid var(--border);border-radius:8px;font-size:14px;color:var(--text);background:var(--inset)}
.filters{display:flex;flex-wrap:wrap;gap:12px 16px;align-items:flex-end;padding:12px 14px;border:1px solid var(--border);border-radius:10px;background:var(--card);margin-bottom:10px}
.filters-inline{align-items:center}
.filters fieldset{border:0;margin:0;padding:0;min-width:0}
.filters legend,.f-field>span{display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600;margin-bottom:4px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:6px;min-height:36px;padding:4px 10px;border-radius:18px;border:1px solid var(--border-strong);background:var(--card);color:var(--muted);font:inherit;font-size:13px;cursor:pointer}
.chip[aria-pressed="true"]{color:var(--text);font-weight:600;background:var(--accent-tint);border-color:var(--accent)}
.chip[aria-pressed="false"]{text-decoration:line-through}
.chip-n{font-weight:700}
.chip-critical .meter{color:var(--sev-critical)} .chip-high .meter{color:var(--sev-high)} .chip-medium .meter{color:var(--sev-medium)} .chip-low .meter{color:var(--sev-low)}
select,input[type="search"]{font:inherit;font-size:13px;min-height:36px;padding:6px 10px;border:1px solid var(--border-strong);border-radius:8px;background:var(--card);color:var(--text);max-width:100%}
.f-file input{width:200px}
.count{color:var(--muted);font-size:12px;margin:6px 2px 10px}
.empty{border:1px dashed var(--border-strong);border-radius:10px;padding:24px;text-align:center;background:var(--inset)}
.empty h3{font-size:15px;margin-bottom:6px}
.empty p{color:var(--muted);margin:0 0 12px}
.flist{display:grid;gap:10px}
.fcard{border:1px solid var(--border);border-left:4px solid var(--border-strong);border-radius:10px;background:var(--card);box-shadow:0 1px 2px var(--shadow)}
.fcard-critical{border-left-color:var(--sev-critical)} .fcard-high{border-left-color:var(--sev-high)} .fcard-medium{border-left-color:var(--sev-medium)} .fcard-low{border-left-color:var(--sev-low)}
.fcard>summary{list-style:none;display:grid;grid-template-columns:auto auto minmax(0,1fr);grid-template-areas:"b r t" ". . m";gap:4px 10px;align-items:center;padding:12px 16px;min-height:44px;cursor:pointer}
.fcard>summary::-webkit-details-marker{display:none}
.fcard>summary::after{content:"";grid-area:t;justify-self:end;width:8px;height:8px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(-45deg);transition:transform .15s ease-out}
.fcard[open]>summary::after{transform:rotate(45deg)}
.fcard>summary .sev{grid-area:b}.fcard>summary .rid{grid-area:r}
.ftitle{grid-area:t;font-weight:600;padding-right:24px}
.fmeta{grid-area:m;display:flex;flex-wrap:wrap;gap:4px 10px;align-items:center;font-size:12px;color:var(--muted)}
.fcard[open]>summary{border-bottom:1px solid var(--border-subtle)}
.fcard.is-target{box-shadow:0 0 0 2px var(--accent)}
.fbody{padding:14px 16px 16px}
.fmsg{margin:0 0 12px;font-size:15px;max-width:90ch}
.fcols{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:24px}
.fbody h4{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:14px 0 6px}
.fmain h4:first-child,.fside h4:first-child{margin-top:0}
.fbody p{margin:0}
.fbody .fmsg{margin:0 0 16px}
.fside .cmd{white-space:pre-wrap;word-break:break-word}
.flow{list-style:none;margin:0;padding:0;counter-reset:s;position:relative}
.step{position:relative;display:grid;grid-template-columns:28px auto auto minmax(0,1fr);grid-template-areas:"n role loc note" ". code code code";gap:4px 8px;align-items:center;padding:8px 0 8px}
.step+.step::before{content:"";position:absolute;left:13px;top:-10px;height:18px;border-left:2px solid var(--border-strong)}
.step-n{grid-area:n;display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:13px;border:2px solid var(--border-strong);font-weight:700;font-size:12px;background:var(--card)}
.step-source .step-n{border-color:var(--source);color:var(--source)}
.step-sink .step-n{border-color:var(--sink);color:var(--sink)}
.role{grid-area:role;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.role-source{color:var(--source)} .role-sink{color:var(--sink)}
.step .loc{grid-area:loc}
.step-note{grid-area:note;font-size:12px;color:var(--dim)}
.step-code{grid-area:code}
.snip{display:block;padding:6px 10px;border-radius:6px;background:var(--inset);border:1px solid var(--border-subtle);color:var(--text);white-space:pre;overflow-x:auto}
html[data-wrap="1"] .snip{white-space:pre-wrap;word-break:break-all}
.nf{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.fside{border-left:1px solid var(--border-subtle);padding-left:20px}
.locs{list-style:none;margin:0;padding:0;font-size:12px}
.locs li{padding:2px 0}
.copyrow{display:flex;gap:6px;align-items:flex-start;margin:4px 0}
.cmd{flex:1;min-width:0;margin:0;padding:7px 10px;border-radius:6px;background:var(--inset);border:1px solid var(--border-subtle);overflow-x:auto;white-space:pre}
.ctl{display:inline-block;font-family:var(--mono);font-size:10px;padding:0 4px;margin:0 1px;border-radius:3px;border:1px solid var(--sev-critical-border);color:var(--sev-critical);background:var(--sev-critical-tint)}
.callout{padding:10px 14px;border:1px solid var(--accent);border-radius:8px;background:var(--accent-tint);margin-bottom:16px}
.tscroll{overflow-x:auto;border:1px solid var(--border);border-radius:10px;background:var(--card)}
.panel .tscroll{border:0;border-radius:0}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th,.tbl td{text-align:left;vertical-align:top;padding:9px 12px;border-top:1px solid var(--border-subtle)}
.tbl thead th{border-top:0;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600;background:var(--inset);white-space:nowrap}
.tbl tbody th{font-weight:600}
.tbl-kv th{width:200px;color:var(--muted);font-weight:500}
.num{text-align:right}
.state{font-size:12px;font-weight:600}
.state-on{color:var(--text)} .state-off{color:var(--muted);text-decoration:line-through}
.ready{font-size:11px;border:1px dashed var(--border-strong);border-radius:4px;padding:1px 6px;color:var(--muted);white-space:nowrap}
.just{font-style:normal;quotes:"\201C" "\201D"}
.flag-new{display:inline-block;margin-left:6px;font-size:11px;font-weight:700;letter-spacing:.04em;padding:0 6px;border-radius:4px;color:var(--accent-text);border:1px solid var(--accent);background:var(--accent-tint)}
.sstate{font-weight:600}
.sstate-warn{color:var(--sev-medium)} .sstate-rejected{color:var(--sev-critical)} .sstate-stale{color:var(--muted)}
.weak{margin:0;padding-left:18px} .weak li{margin:4px 0}
.fw-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:6px}
.fw{border:1px solid var(--border);border-radius:10px;padding:12px 14px;background:var(--card)}
.fw-head{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:4px}
.fw p{margin:0;font-size:12px}
.fw-meta{margin-top:8px!important;color:var(--muted)}
.graph-wrap{overflow-x:auto;border:1px solid var(--border-subtle);border-radius:8px;background:var(--page)}
.agraph{display:block;width:100%;min-width:900px;height:auto}
.g-col{font:700 11px var(--body);letter-spacing:.06em;fill:var(--muted)}
.g-edge{fill:none;stroke:var(--graph-edge);stroke-width:1.5}
.g-cycle{stroke-dasharray:5 4}
.arrowhead{fill:var(--graph-edge)}
.g-elabel{font:11px var(--body);fill:var(--muted)}
.g-node rect{fill:var(--graph-node);stroke:var(--border-strong);stroke-width:1.2}
.g-input rect{stroke-dasharray:4 3}
.g-agent rect{stroke:var(--text);stroke-width:1.8}
.g-sink rect{fill:var(--inset)}
.g-lab{font:600 12.5px var(--mono);fill:var(--text)}
.g-sub{font:11px var(--body);fill:var(--muted)}
.g-mark text{font:700 10.5px var(--mono);letter-spacing:.02em}
.g-m-critical rect{fill:var(--failed-fill)} .g-m-critical text{fill:var(--failed-on)}
.g-m-high rect{fill:var(--card);stroke:var(--sev-high)} .g-m-high text{fill:var(--sev-high)}
.g-m-medium rect{fill:var(--card);stroke:var(--sev-medium)} .g-m-medium text{fill:var(--sev-medium)}
.g-m-low rect{fill:var(--card);stroke:var(--sev-low)} .g-m-low text{fill:var(--sev-low)}
.g-m-info rect{fill:var(--card);stroke:var(--border-strong);stroke-dasharray:3 2} .g-m-info text{fill:var(--muted)}
.g-legend{list-style:none;display:flex;flex-wrap:wrap;gap:6px 18px;margin:10px 0 0;padding:0;font-size:12px;color:var(--muted)}
.g-legend li{display:flex;align-items:center;gap:6px}
.lg{display:inline-block;width:22px;height:12px;border:1.5px solid var(--border-strong);border-radius:3px;background:var(--graph-node)}
.lg-input{border-style:dashed}.lg-agent{border-color:var(--text);border-width:2px}.lg-tool{border-radius:6px}.lg-sink{background:var(--inset)}
.lg-cycle{border:0;border-top:2px dashed var(--graph-edge);height:0;border-radius:0;background:none}
.run-meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0}
.run-meta div{border:1px solid var(--border-subtle);border-radius:8px;padding:8px 10px;background:var(--inset)}
.run-meta dt{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.run-meta dd{margin:2px 0 0;font-weight:500}
.ph-0,.ph-sw-0{fill:var(--accent);background:var(--accent)}
.ph-1,.ph-sw-1{fill:var(--sev-low);background:var(--sev-low)}
.ph-2,.ph-sw-2{fill:var(--text);background:var(--text)}
.ph-3,.ph-sw-3{fill:var(--muted);background:var(--muted)}
.src{font-size:12px;border-radius:4px;padding:1px 6px;border:1px solid var(--border);white-space:nowrap}
.src-cli{border-color:var(--accent);color:var(--accent-text)}
.src-file{border-color:var(--border-strong);color:var(--text);font-weight:600}
.src-default{color:var(--muted)}
.weakv{color:var(--text);font-weight:600}
.tbl .loc{white-space:nowrap;word-break:normal}
.note+.panel,.tscroll+.note+.panel{margin-top:16px}
.rchips{list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:6px;margin:0;padding:0}
.rchip{display:flex;justify-content:space-between;gap:6px;align-items:center;padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:var(--card)}
.rchip-off{background:var(--inset);border-style:dashed}
.prefs{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.prefs fieldset{border:1px solid var(--border-subtle);border-radius:8px;padding:10px 12px;margin:0}
.prefs legend{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600;padding:0 4px}
.radio,.check{display:flex;gap:8px;align-items:center;min-height:32px}
.radio input,.check input{width:18px;height:18px;accent-color:var(--accent)}
.lbl{margin:14px 0 4px!important;font-weight:600;font-size:13px}
.plain{margin:0;padding-left:18px}.plain li{margin:4px 0}
.scrim{display:none}
html[data-density="compact"] .fcard>summary{padding:8px 12px}
html[data-density="compact"] .tbl th,html[data-density="compact"] .tbl td{padding:6px 10px}
html[data-density="compact"] .tile{min-height:80px;padding:10px 12px}
@media (max-width:1180px){.tiles{grid-template-columns:repeat(4,minmax(0,1fr))}.fw-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:900px){
  .shell{grid-template-columns:minmax(0,1fr)}
  .btn-icon.menu-btn{display:inline-flex}
  html.js .nav{position:fixed;left:0;top:0;bottom:0;z-index:20;width:280px;transform:translateX(-100%);transition:transform .15s ease-out;box-shadow:0 0 24px var(--shadow)}
  html.js.nav-open .nav{transform:none}
  html.js.nav-open .scrim{display:block;position:fixed;inset:0;z-index:15;background:var(--scrim)}
  html:not(.js) .nav{position:static;height:auto}
  html:not(.js) .shell{display:block}
  .btn-icon.nav-close{display:inline-flex}
  .grid-2,.fcols{grid-template-columns:minmax(0,1fr)}
  .fside{border-left:0;padding-left:0;border-top:1px solid var(--border-subtle);padding-top:12px}
  .prefs{grid-template-columns:minmax(0,1fr)}
  .run-meta{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media (max-width:600px){
  .topbar{padding:8px 16px;gap:10px}
  .content{padding:16px 16px 40px}
  .tiles,.tiles-4,.fw-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .status-detail,.exit-chip,#themeLabel,.target-val .meta,.target-val .sep{display:none}
  .theme-btn{min-width:40px;justify-content:center}
  .f-file input{width:100%}
  .filters>*{flex:1 1 100%}
  .strip-link{margin-left:0}
  .view-head h1{font-size:20px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media print{.nav,.topbar,.mockband,.filters,.copy,.scrim{display:none!important}.shell{display:block}html.js .view{display:block!important}}
"""

JS = r"""
(function(){
  var d=document.documentElement; d.classList.add('js');
  var KEY='__KEY__';
  function load(){try{var v=window.localStorage.getItem(KEY);return v?JSON.parse(v):{};}catch(e){return null;}}
  function save(p){try{window.localStorage.setItem(KEY,JSON.stringify(p));return true;}catch(e){return false;}}
  var stored=load(); var storageOk=stored!==null; var prefs=stored||{};
  var q=window.location.search;
  var qTheme=/[?&]theme=(light|dark)/.exec(q); var qScan=/[?&]scan=(partial|complete)/.exec(q);
  var qNav=/[?&]nav=open/.test(q);
  function $(s,r){return (r||document).querySelector(s);} function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));}
  function applyPrefs(){
    var t=qTheme?qTheme[1]:(prefs.theme||'system');
    if(t==='system'){d.removeAttribute('data-theme');}else{d.setAttribute('data-theme',t);}
    var lab=$('#themeLabel'); if(lab){lab.textContent='Theme: '+t;}
    d.setAttribute('data-density',prefs.density||'comfortable');
    d.setAttribute('data-wrap',prefs.wrap_code?'1':'0');
    var f=$('#prefs'); if(f){
      $$('input[name="theme"]',f).forEach(function(i){i.checked=(i.value===(prefs.theme||'system'));});
      $$('input[name="density"]',f).forEach(function(i){i.checked=(i.value===(prefs.density||'comfortable'));});
      f.elements.show_low_info.checked=prefs.show_low_info!==false; f.elements.wrap_code.checked=!!prefs.wrap_code;}
  }
  function persist(){
    var ok=save(prefs); var s=$('#prefStatus');
    if(s){s.textContent=ok?'Saved in this browser only. Preferences never change the scan, the config file or the result.':'Could not save: this browser blocks local storage here. Preferences apply until you close this tab.';}
  }
  applyPrefs();
  if(!storageOk){var s0=$('#prefStatus'); if(s0){s0.textContent='Local storage is not available in this browser. Preferences apply until you close this tab.';}}
  if(qScan){d.setAttribute('data-scan',qScan[1]);}
  $$('[data-scan-set]').forEach(function(b){
    b.setAttribute('aria-pressed',String((d.getAttribute('data-scan')||'complete')===b.getAttribute('data-scan-set')));
    b.addEventListener('click',function(){d.setAttribute('data-scan',b.getAttribute('data-scan-set'));
      $$('[data-scan-set]').forEach(function(x){x.setAttribute('aria-pressed',String(x===b));});});});
  var order=['system','light','dark'];
  $('#themeBtn').addEventListener('click',function(){var c=prefs.theme||'system';prefs.theme=order[(order.indexOf(c)+1)%3];qTheme=null;applyPrefs();persist();});
  var pf=$('#prefs'); if(pf){pf.addEventListener('change',function(){
    prefs.theme=pf.elements.theme.value; prefs.density=pf.elements.density.value;
    prefs.show_low_info=pf.elements.show_low_info.checked; prefs.wrap_code=pf.elements.wrap_code.checked;
    qTheme=null; applyPrefs(); persist();});}
  // narrow menu
  var nav=$('#nav'), mb=$('#menuBtn');
  function setNav(open){d.classList.toggle('nav-open',open); mb.setAttribute('aria-expanded',String(open)); if(open){var a=$('.nav-link[aria-current="page"]')||$('.nav-link'); a.focus();}}
  mb.addEventListener('click',function(){setNav(!d.classList.contains('nav-open'));});
  $('#navClose').addEventListener('click',function(){setNav(false);mb.focus();});
  $('#scrim').addEventListener('click',function(){setNav(false);});
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape'&&d.classList.contains('nav-open')){setNav(false);mb.focus();}
    if(e.key==='/'&&!/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)){var ff=$('#fFile'); if(ff&&$('#findings').classList.contains('active')){e.preventDefault();ff.focus();}}
  });
  // findings filters
  var cards=$$('#flist .fcard');
  function filt(){
    var sev={}; $$('.chip[data-sev]').forEach(function(c){sev[c.getAttribute('data-sev')]=c.getAttribute('aria-pressed')==='true';});
    var a=$('#fAsi').value, r=$('#fRule').value, f=$('#fFile').value.trim().toLowerCase(), n=0;
    cards.forEach(function(c){var ok=sev[c.getAttribute('data-sev')]&&(!a||(' '+c.getAttribute('data-asi')+' ').indexOf(' '+a+' ')>=0)&&(!r||c.getAttribute('data-rule')===r)&&(!f||c.getAttribute('data-file').toLowerCase().indexOf(f)>=0);
      c.hidden=!ok; if(ok){n++;}});
    $('#fCount').textContent='Showing '+n+' of '+cards.length+' findings'; $('#fEmpty').hidden=n!==0;
  }
  function clearF(){$$('.chip[data-sev]').forEach(function(c){c.setAttribute('aria-pressed','true');}); $('#fAsi').value=''; $('#fRule').value=''; $('#fFile').value=''; filt();}
  $$('.chip[data-sev]').forEach(function(c){c.addEventListener('click',function(){c.setAttribute('aria-pressed',String(c.getAttribute('aria-pressed')!=='true'));filt();});});
  ['#fAsi','#fRule'].forEach(function(s){$(s).addEventListener('change',filt);}); $('#fFile').addEventListener('input',filt);
  $('#fClear').addEventListener('click',clearF); $('#fClear2').addEventListener('click',clearF);
  $('#filters').addEventListener('submit',function(e){e.preventDefault();});
  if(prefs.show_low_info===false){$$('.chip[data-sev="low"],.chip[data-sev="info"]').forEach(function(c){c.setAttribute('aria-pressed','false');});}
  filt();
  // rules filter
  var rrows=$$('#rtable tbody tr');
  $('#rAsi').addEventListener('change',function(){var v=this.value,n=0; rrows.forEach(function(tr){var ok=!v||(' '+tr.getAttribute('data-asi')+' ').indexOf(' '+v+' ')>=0; tr.hidden=!ok; if(ok){n++;}}); $('#rCount').textContent='Showing '+n+' rules';});
  // copy
  $$('.copy').forEach(function(b){b.addEventListener('click',function(){
    var t=b.getAttribute('data-copy'); function done(w){b.textContent=w; setTimeout(function(){b.textContent='Copy';},1600);}
    try{navigator.clipboard.writeText(t).then(function(){done('Copied');},function(){done('Select and copy');});}catch(e){done('Select and copy');}});});
  // routing
  var views=$$('.view'), links=$$('.nav-link');
  function route(){
    var h=decodeURIComponent(window.location.hash.slice(1))||'overview', parts=h.split('/'), v=parts[0];
    if(!$('#'+v)||!$('#'+v).classList.contains('view')){var el=document.getElementById(h); var p=el&&el.closest?el.closest('.view'):null; v=p?p.id:'overview';}
    views.forEach(function(s){s.classList.toggle('active',s.id===v);});
    links.forEach(function(a){if(a.getAttribute('data-view')===v){a.setAttribute('aria-current','page');}else{a.removeAttribute('aria-current');}});
    document.title=($('.nav-link[data-view="'+v+'"] .nav-text')||{textContent:''}).textContent+' - nexvul report';
    setNav(false);
    var arg=parts[1]||'', target=null;
    if(v==='findings'){
      cards.forEach(function(c){c.classList.remove('is-target');});
      if(/^sev=/.test(arg)){var s=arg.slice(4); $$('.chip[data-sev]').forEach(function(c){c.setAttribute('aria-pressed',String(c.getAttribute('data-sev')===s));}); $('#fAsi').value='';$('#fRule').value='';$('#fFile').value=''; filt();}
      else if(/^rule=/.test(arg)){clearF(); $('#fRule').value=arg.slice(5); filt();}
      else if(/^F\d+$/.test(arg)){target=$('#f-'+arg); if(target){clearF(); cards.forEach(function(c){if(c!==target){c.open=false;}}); target.open=true; target.classList.add('is-target');}}
    }
    pending={el:target,top:!target&&!(v==='settings'&&arg==='change')}; doScroll();
  }
  var pending=null;
  function doScroll(){if(!pending){return;} if(pending.el){pending.el.scrollIntoView({block:'start'}); window.scrollBy(0,-72);} else if(pending.top){window.scrollTo(0,0);}}
  if('scrollRestoration' in history){history.scrollRestoration='manual';}
  window.addEventListener('hashchange',route); route();
  window.addEventListener('load',function(){setTimeout(doScroll,0);});
  if(qNav){setNav(true);}
})();
"""


def build():
    css = css_vars() + CSS
    js = JS.replace("__KEY__", TOKENS["storage"]["report_prefs_key"])
    csp = ("default-src 'none'; style-src %s; script-src %s; img-src data:; base-uri 'none'; form-action 'none'"
           % (csp_hash(css), csp_hash(js)))
    views = v_overview() + v_findings() + v_agents() + v_rules() + v_suppressions() + v_history() + v_settings() + v_help()
    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="%(csp)s">
<meta name="referrer" content="no-referrer">
<title>nexvul report</title>
<style>%(css)s</style>
</head>
<body>
<div class="mockband" role="note"><strong>%(mock)s</strong><span>Invented project. Rules are design only; nothing here is a real scan.</span>
  <span class="seg-ctl" aria-label="Preview scan state (design review only, not in the product)">Preview state:
    <button type="button" data-scan-set="complete" aria-pressed="true">Complete</button>
    <button type="button" data-scan-set="partial" aria-pressed="false">Partial</button></span></div>
<div class="shell">
%(nav)s
<div class="scrim" id="scrim"></div>
<div class="maincol">
%(topbar)s
<main class="content" id="main">
%(views)s
</main>
<footer class="content foot note">nexvul %(ver)s &middot; rules %(rh)s &middot; %(disc)s &middot; %(mock)s</footer>
</div>
</div>
<script>%(js)s</script>
</body>
</html>
""" % dict(csp=csp, css=css, mock=MOCK_LABEL, nav=nav(), topbar=topbar(), views=views, ver=S["version"],
           rh=esc(S["rules_hash"]), disc=esc(TOKENS["copy"]["disclaimer"]), js=js)
    check_balanced(page, "report-preview.html")
    check_colours(page, "report-preview.html")
    check_no_handlers(page, "report-preview.html")
    check_no_network(page, "report-preview.html")
    assert "&lt;img src=x onerror=alert(1)&gt;" in page, "hostile filename must be escaped"
    assert "<img src=x" not in page
    open(OUT, "w").write(page)
    print("wrote", OUT, len(page), "bytes")


def shots():
    os.makedirs(SHOTS, exist_ok=True)
    u = "file://" + OUT
    jobs = [
        ("dashboard-hero.png", "?theme=light#overview", 1280, 800, False),
        ("dashboard-full.png", "?theme=light#overview", 1280, 2400, True),
        ("dashboard-findings-expanded.png", "?theme=light#findings", 1280, 1500, False),
        ("dashboard-findings-filtered-empty.png", "?theme=light#findings/sev=info", 1280, 760, False),
        ("dashboard-agent-map.png", "?theme=light#agents", 1280, 2000, True),
        ("dashboard-rules.png", "?theme=light#rules", 1280, 2600, True),
        ("dashboard-suppressions.png", "?theme=light#suppressions", 1280, 2000, True),
        ("dashboard-history-partial.png", "?theme=light&scan=partial#history", 1280, 2000, True),
        ("dashboard-settings.png", "?theme=light#settings", 1280, 2600, True),
        ("dashboard-help.png", "?theme=light#help", 1280, 2000, True),
        ("dashboard-overview-partial.png", "?theme=light&scan=partial#overview", 1280, 900, False),
        ("dashboard-overview-dark.png", "?theme=dark#overview", 1280, 800, False),
        ("dashboard-mobile.png", "?theme=light#overview", 390, 1400, False),
        ("dashboard-mobile-menu.png", "?theme=light&nav=open#findings", 390, 844, False),
    ]
    for name, q, w, h, crop in jobs:
        if w < 500:  # headless Chrome enforces a 500px minimum window: render inside a phone-width iframe
            harness = os.path.join(os.path.dirname(__file__), "_phone_harness.html")
            open(harness, "w").write('<!doctype html><meta charset="utf-8"><body style="margin:0">'
                                     '<iframe src="%s" width="%d" height="%d" style="border:0;display:block">'
                                     '</iframe>' % (u + q, w, h))
            out = os.path.join(SHOTS, name)
            shoot("file://" + harness, out, 500, h, crop=False)
            from PIL import Image
            Image.open(out).crop((0, 0, w, h)).save(out)
            os.remove(harness)
            print("shot", name)
            continue
        shoot(u + q, os.path.join(SHOTS, name), w, h, crop=crop, crop_x=240 if w > 900 else 0)
        print("shot", name)


if __name__ == "__main__":
    build()
    if "--shots" in sys.argv:
        shots()
