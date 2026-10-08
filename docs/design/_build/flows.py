"""Render nexvul user-journey flows as SVG swimlanes.

Design tooling only (not shipped). Data-driven: edit JOURNEYS, re-run.
Usage: python3 -I flows.py <docs/design dir>
Colours come from tokens.json (light theme) so no colour is defined here.
"""
import json
import pathlib
import sys
from xml.sax.saxutils import escape

COL_W, NODE_W, NODE_H, LANE_H, FAIL_H, PAD = 190, 160, 58, 110, 70, 20

# (lane, kind, label, screen ids, [failure branches as (label, ids)])
# kind: start | step | decision | end
JOURNEYS = {
    "J1-first-run": {
        "title": "J1 First run on a local repo (AI app developer)",
        "lanes": ["Developer", "nexvul CLI"],
        "nodes": [
            (0, "start", "Reads README hero", "D01", []),
            (0, "step", "pipx install nexvul", "D02", [("Python < 3.12", "U05")]),
            (0, "step", "nexvul scan .", "T01", [("Bad path / flag", "T10 · exit 2"), ("Bad .nexvul.yml", "T09 · exit 2")]),
            (1, "decision", "Anything to analyse?", "T18", [("No: SCAN FAILED", "T18 · exit 3")]),
            (1, "decision", "Framework recognised?", "T19", [("No: note, rules idle", "T19")]),
            (1, "decision", "All files analysed?", "T05 T06", [("No: PARTIAL banner last", "T05/T06 · exit 3")]),
            (1, "decision", "Findings?", "T02 T04", [("None: scope statement", "T02 · exit 0")]),
            (0, "step", "nexvul explain NEX0nn", "U03", []),
            (0, "end", "Fixes, re-scans", "T03/T02", [("Ctrl-C", "T20 · 130"), ("nexvul crash", "T11 · exit 4")]),
        ],
    },
    "J2-triage": {
        "title": "J2 Triage an alert in GitHub code scanning (AppSec engineer)",
        "lanes": ["AppSec engineer", "GitHub", "Developer"],
        "nodes": [
            (0, "start", "Opens alerts, tool:nexvul", "G01", []),
            (1, "step", "Alert: message, location, paths", "G02", [("Attacker text in snippet", "G02 escaped")]),
            (1, "step", "Rule help panel", "G03", []),
            (0, "decision", "Run complete?", "G05 A03", [("Partial: list may be short", "A03")]),
            (0, "decision", "Flow real?", "G02", [("Misread: dismiss + FP report", "G03 link")]),
            (0, "decision", "Mitigated elsewhere?", "", [("Yes: suppress in code (J3)", "C03")]),
            (2, "step", "Reproduce locally", "U03 T12", []),
            (2, "end", "Fix assigned", "G01", []),
        ],
    },
    "J3-suppress": {
        "title": "J3 Suppress a false positive with a justification",
        "lanes": ["Developer", "nexvul", "Reviewer (CI)"],
        "nodes": [
            (0, "start", "Sees finding", "T04", []),
            (0, "step", "nexvul explain: syntax", "U03", []),
            (0, "step", "Adds ignore[NEX0nn] -- reason", "C03", []),
            (1, "decision", "Valid suppression?", "C05", [("No rule ID / hidden chars", "C05 · stays active")]),
            (1, "decision", "Justification (CI)?", "C04", [("Missing: stays active", "C04")]),
            (1, "step", "Shown as Suppressed", "T17", [("Matched nothing: stale", "T17 note")]),
            (2, "step", "Summary: added in this PR", "A01", [("Rule disabled in PR config", "C06 · not applied")]),
            (2, "end", "Alert suppressed in source", "G04", []),
        ],
    },
    "J4-ci-gating": {
        "title": "J4 Gate CI with fail-on (platform engineer)",
        "lanes": ["Platform engineer", "nexvul Action", "GitHub"],
        "nodes": [
            (0, "start", "Copies reference workflow", "D06", []),
            (0, "step", "Commits .nexvul.yml + CODEOWNERS", "C01", []),
            (1, "decision", "Safe trigger?", "A06", [("pull_request_target", "A06 · refused")]),
            (1, "step", "CI mode, base-ref config", "T23", [("Bad input", "A08 · exit 2")]),
            (1, "decision", "Scan complete?", "A03", [("Partial / failed", "A03 · exit 3")]),
            (1, "decision", "Findings >= fail-on?", "A01 A02", [("Yes", "A01 · exit 1")]),
            (2, "step", "SARIF upload", "G01", [("Upload failed / fork", "A07")]),
            (2, "end", "Job result is the gate", "A05", [("nexvul crash", "A09 · exit 4")]),
        ],
    },
    "J5-contribute-rule": {
        "title": "J5 Contribute a rule (open-source contributor)",
        "lanes": ["Contributor", "Maintainer", "CI"],
        "nodes": [
            (0, "start", "CONTRIBUTING: propose a rule", "D05", []),
            (0, "step", "Checks existing rules", "U01 U03", []),
            (0, "step", "Opens rule proposal", "D05", []),
            (1, "decision", "In scope?", "", [("Out of scope: reason given", "taxonomy §5")]),
            (1, "step", "Allocates NEX0nn", "", []),
            (0, "step", "Rule + tests + docs", "D04", []),
            (2, "decision", "Lints pass?", "", [("Unsafe message / link / banned word", "J5-F1..F3")]),
            (2, "decision", "Meets FP budget?", "", [("No: failing safe/ cases listed", "DEC-0002")]),
            (1, "end", "Merged as experimental", "U01", []),
        ],
    },
}


def load_palette(design_dir: pathlib.Path) -> dict:
    t = json.loads((design_dir / "tokens.json").read_text(encoding="utf-8"))["color"]["light"]
    return {
        "page": t["surface"]["page"], "card": t["surface"]["card"], "inset": t["surface"]["inset"],
        "border": t["border"]["default"], "ink": t["text"]["default"]["value"],
        "muted": t["text"]["muted"]["value"], "accent": t["accent"]["text"]["value"],
        "fail": t["severity"]["critical"]["text"], "decision": t["severity"]["medium"]["text"],
        "end": t["text"]["default"]["value"],
    }


def text(x, y, s, size=12, fill="ink", weight=400, anchor="middle"):
    return (f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
            f'fill="var(--{fill})">{escape(s)}</text>')


def wrap(s, n=24):
    words, lines, cur = s.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > n and cur:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    lines.append(cur)
    return lines[:3]


def render(name, j, pal):
    lanes, nodes = j["lanes"], j["nodes"]
    max_fail = max(len(n[4]) for n in nodes)
    width = 140 + COL_W * len(nodes)
    lanes_h = LANE_H * len(lanes)
    height = 60 + lanes_h + 30 + FAIL_H * max_fail + 20
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
           f'height="{height}" font-family="-apple-system, Segoe UI, Roboto, sans-serif">',
           "<style>:root{" + ";".join(f"--{k}:{v}" for k, v in pal.items()) + "}</style>",
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
           'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--muted)"/></marker></defs>',
           f'<rect width="{width}" height="{height}" fill="var(--page)"/>',
           text(PAD, 32, j["title"], 16, "ink", 700, "start")]
    top = 50
    for i, lane in enumerate(lanes):
        y = top + i * LANE_H
        out.append(f'<rect x="{PAD}" y="{y}" width="{width - 2 * PAD}" height="{LANE_H}" fill="var(--card)" '
                   f'stroke="var(--border)"/>')
        out.append(text(PAD + 8, y + 20, lane.upper(), 11, "muted", 600, "start"))
    fail_top = top + lanes_h + 30
    out.append(text(PAD, fail_top - 10, "FAILURE BRANCHES", 11, "fail", 600, "start"))
    centers = []
    for k, (lane, kind, label, ids, fails) in enumerate(nodes):
        cx = 140 + COL_W * k + NODE_W / 2 - 40
        cy = top + lane * LANE_H + LANE_H / 2 + 6
        centers.append((cx, cy))
        x0, y0 = cx - NODE_W / 2, cy - NODE_H / 2
        stroke = {"decision": "decision", "end": "end", "start": "accent"}.get(kind, "border")
        if kind == "decision":
            pts = f"{cx},{y0 - 6} {x0 + NODE_W + 6},{cy} {cx},{y0 + NODE_H + 6} {x0 - 6},{cy}"
            out.append(f'<polygon points="{pts}" fill="var(--card)" stroke="var(--{stroke})" stroke-width="2"/>')
        else:
            r = 29 if kind in ("start", "end") else 6
            out.append(f'<rect x="{x0}" y="{y0}" width="{NODE_W}" height="{NODE_H}" rx="{r}" fill="var(--card)" '
                       f'stroke="var(--{stroke})" stroke-width="{2 if kind != "step" else 1.5}"/>')
        lines = wrap(label, 15 if kind == "decision" else (20 if kind in ("start", "end") else 26))
        for li, ln in enumerate(lines):
            out.append(text(cx, cy - 6 * (len(lines) - 1) + li * 13 - 2, ln, 11.5, "ink", 600))
        if ids:
            out.append(text(cx, y0 + NODE_H + (20 if kind == "decision" else 14), ids, 10.5, "accent", 600))
        for fi, (flabel, fids) in enumerate(fails):
            fy = fail_top + fi * FAIL_H
            out.append(f'<path d="M{cx},{cy + NODE_H / 2 + 22} L{cx},{fy}" stroke="var(--fail)" '
                       f'stroke-dasharray="4 3" fill="none" marker-end="url(#arr)"/>' if fi == 0 else "")
            out.append(f'<rect x="{x0 + 6}" y="{fy}" width="{NODE_W - 12}" height="{FAIL_H - 14}" rx="4" '
                       f'fill="var(--inset)" stroke="var(--fail)"/>')
            for li, ln in enumerate(wrap("✕ " + flabel, 24)[:2]):
                out.append(text(cx, fy + 18 + li * 13, ln, 10.5, "ink"))
            out.append(text(cx, fy + FAIL_H - 22, fids, 10, "fail", 600))
    for (ax, ay), (bx, by) in zip(centers, centers[1:]):
        sx, ex = ax + NODE_W / 2 + 4, bx - NODE_W / 2 - 8
        if ay == by:
            out.append(f'<path d="M{sx},{ay} L{ex},{by}" stroke="var(--muted)" fill="none" marker-end="url(#arr)"/>')
        else:
            mx = (sx + ex) / 2
            out.append(f'<path d="M{sx},{ay} L{mx},{ay} L{mx},{by} L{ex},{by}" stroke="var(--muted)" fill="none" '
                       f'marker-end="url(#arr)"/>')
    out.append("</svg>")
    return "\n".join(o for o in out if o)


def main(design_dir):
    d = pathlib.Path(design_dir)
    pal = load_palette(d)
    (d / "flows").mkdir(exist_ok=True)
    for name, j in JOURNEYS.items():
        svg = render(name, j, pal)
        assert svg.count("<rect") + svg.count("<polygon") > 0
        (d / "flows" / f"{name}.svg").write_text(svg, encoding="utf-8")
        print(f"wrote flows/{name}.svg ({len(j['nodes'])} nodes)")


if __name__ == "__main__":
    main(sys.argv[1])
