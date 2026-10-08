"""Shared helpers for the nexvul design generators.

Every colour used by generated pages comes from docs/design/tokens.json via css_vars().
Every string that would come from a scanned repository goes through esc() (HTML-escape)
and show_ctl() (render control / bidi characters as a visible code-point token).
"""
import hashlib
import html
import json
import os
import re
import subprocess
import unicodedata

ROOT = "/Users/innovations/nexvul"
DESIGN = os.path.join(ROOT, "docs", "design")
TOKENS = json.load(open(os.path.join(DESIGN, "tokens.json")))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

MOCK_LABEL = "Design mock-up, sample data"

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
METER = {k: TOKENS["severity"][k]["meter"] for k in SEV_ORDER}
LABEL = {k: TOKENS["severity"][k]["label"] for k in SEV_ORDER}


def esc(s):
    return html.escape(str(s), quote=True)


_CTL = re.compile(r"[\u0000-\u0008\u000b-\u001f\u007f​-‏‪-‮⁦-⁩﻿]")


def show_ctl(s):
    """Escape for HTML and render control/bidi characters as a visible token (SR-10, H13)."""
    out, last = [], 0
    for m in _CTL.finditer(s):
        out.append(esc(s[last:m.start()]))
        cp = ord(m.group(0))
        name = unicodedata.name(m.group(0), "CONTROL")
        out.append('<span class="ctl" title="%s">U+%04X</span>' % (esc(name), cp))
        last = m.end()
    out.append(esc(s[last:]))
    return "".join(out)


def trunc(s, n):
    """Truncate with an ellipsis and a 6-hex hash suffix of the full value (tokens.truncation)."""
    if len(s) <= n:
        return s
    h = hashlib.sha256(s.encode()).hexdigest()[:6]
    return s[: n - 10] + "…[" + h + "]"


def _vars(theme):
    c = TOKENS["color"][theme]
    s, b, t, a, sev, st, fl, app = (c["surface"], c["border"], c["text"], c["accent"], c["severity"],
                                    c["status"], c["flow"], c["app"])
    v = {
        "page": s["page"], "raised": s["raised"], "card": s["card"], "card-hover": s["card_hover"],
        "inset": s["inset"], "nav": s["nav"],
        "border": b["default"], "border-subtle": b["subtle"], "border-strong": b["strong"],
        "text": t["default"]["value"], "muted": t["muted"]["value"], "dim": t["dim"]["value"],
        "accent": a["fill"], "accent-text": a["text"]["value"], "accent-tint": a["tint"],
        "partial-fill": st["partial"]["fill"], "partial-on": st["partial"]["on_fill"],
        "failed-fill": st["failed"]["fill"], "failed-on": st["failed"]["on_fill"],
        "source": fl["source_marker"], "sink": fl["sink_marker"],
        "hatch": app["hatch"], "shadow": app["shadow"], "scrim": app["scrim"],
        "mock-band": app["mock_band"], "mock-band-text": app["mock_band_text"],
        "graph-edge": app["graph_edge"], "graph-node": app["graph_node_fill"],
    }
    for k in SEV_ORDER:
        v["sev-%s" % k] = sev[k]["text"]
        v["sev-%s-tint" % k] = sev[k]["tint"]
        v["sev-%s-border" % k] = sev[k]["border"]
    return "".join("  --%s: %s;\n" % kv for kv in v.items())


def css_vars():
    """Light is the default (DEC-0009); dark via prefers-color-scheme or data-theme."""
    f = TOKENS["type"]["family"]
    base = ":root {\n" + _vars("light") + "  --mono: %s;\n  --body: %s;\n  color-scheme: light;\n}\n" % (
        f["mono"], f["body"])
    dark = _vars("dark")
    return (base
            + '@media (prefers-color-scheme: dark) {\n  :root:not([data-theme="light"]) {\n' + dark
            + "  color-scheme: dark;\n  }\n}\n"
            + ':root[data-theme="dark"] {\n' + dark + "  color-scheme: dark;\n}\n")


def csp_hash(text):
    import base64
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def mark_svg(size=22):
    return ('<svg class="mark" viewBox="0 0 24 24" width="%d" height="%d" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="4" cy="12" r="2.5" '
            'fill="currentColor"/><circle cx="12" cy="12" r="2.5" fill="currentColor"/><circle cx="20" cy="12" '
            'r="2.5"/><path d="M6.5 12h3M14.5 12h3"/></svg>') % (size, size)


# ---------------------------------------------------------------- verification helpers

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr",
        "circle", "path", "rect", "line", "polyline", "polygon", "ellipse", "stop", "use"}


def check_balanced(markup, name):
    """Tag-balance check: one unclosed tag can blank a whole view."""
    body = re.sub(r"<script\b.*?</script>", "", markup, flags=re.S)
    body = re.sub(r"<style\b.*?</style>", "", body, flags=re.S)
    body = re.sub(r"<!--.*?-->", "", body, flags=re.S)
    stack = []
    for m in re.finditer(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*?)(/?)>", body):
        close, tag, _, selfclose = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
        if tag in ("html", "head", "body", "meta", "title", "link", "!doctype"):
            continue
        if selfclose or (tag in VOID and not close):
            continue
        if close:
            if not stack or stack[-1] != tag:
                raise SystemExit("%s: unbalanced </%s> (stack top %s) near: %s" % (
                    name, tag, stack[-1] if stack else None, body[max(0, m.start() - 120):m.start()]))
            stack.pop()
        else:
            stack.append(tag)
    if stack:
        raise SystemExit("%s: unclosed tags %s" % (name, stack[-5:]))


def token_colours():
    vals = set()

    def walk(o):
        if isinstance(o, dict):
            for x in o.values():
                walk(x)
        elif isinstance(o, list):
            for x in o:
                walk(x)
        elif isinstance(o, str):
            for m in re.findall(r"#[0-9a-fA-F]{6}\b|rgba?\([^)]*\)", o):
                vals.add(m.lower().replace(" ", ""))
    walk(TOKENS["color"])
    return vals


def check_colours(markup, name, extra=()):
    """Every hex / rgba literal in a page must exist in tokens.json."""
    allowed = token_colours() | {x.lower().replace(" ", "") for x in extra}
    found = {m.lower().replace(" ", "") for m in re.findall(r"#[0-9a-fA-F]{6}\b|rgba?\([^)]*\)", markup)}
    bad = sorted(found - allowed)
    if bad:
        raise SystemExit("%s: colours not in tokens.json: %s" % (name, bad))


def check_no_handlers(markup, name):
    for m in re.finditer(r"<[a-zA-Z][^>]*>", markup):
        tag = re.sub(r'"[^"]*"|\'[^\']*\'', '""', m.group(0))
        if re.search(r"\son[a-z]+\s*=", tag) or re.search(r"\sstyle\s*=", tag):
            raise SystemExit("%s: inline handler or style attribute: %s" % (name, m.group(0)[:120]))


def check_no_network(markup, name):
    if re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", markup):
        raise SystemExit("%s: external reference found" % name)


def shoot(url, out, w, h, crop=True, pad=24, crop_x=0):
    """Headless Chrome screenshot; optionally crop trailing blank rows (measured right of crop_x,
    so a full-height sticky side menu does not defeat the crop)."""
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                    "--force-device-scale-factor=1", "--window-size=%d,%d" % (w, h),
                    "--virtual-time-budget=1500", "--screenshot=" + out, url],
                   check=True, capture_output=True)
    if crop:
        from PIL import Image, ImageChops
        im = Image.open(out).convert("RGB")
        region = im.crop((crop_x, 0, im.width, im.height))
        bg = Image.new("RGB", region.size, im.getpixel((im.width - 2, im.height - 2)))
        bbox = ImageChops.difference(region, bg).getbbox()
        if bbox and bbox[3] + pad < im.height:
            im.crop((0, 0, im.width, min(im.height, bbox[3] + pad))).save(out)
    return out
