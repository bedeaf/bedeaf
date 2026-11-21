#!/usr/bin/env python3
"""Generate the SVG panels used by README.md (run from repo root).

Panels are drawn in the black/#a0a0a0 ramp without a background, then
written twice by theme.recolor: a dark and a light copy, which README.md
picks between with <picture> so they sit on GitHub's own page color.
"""
import html

from theme import recolor

FONT = "'Liberation Mono',Menlo,Consolas,monospace"
W = 900
FG, DIM, MID, HI, EDGE = "#a0a0a0", "#707070", "#8f8f8f", "#cfcfcf", "#202020"


def panel(h, body, extra_style="", w=W, inset=0):
    # Frameless: pieces sit straight on the page like terminal output. inset is
    # kept for call compatibility; spacing comes from each panel's padding.
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'font-family="{FONT}">\n<style>{extra_style}</style>\n'
            f'{body}\n</svg>\n')


def disc(attr, pts, T):
    """Looping discrete SMIL animation from (time, value) change points."""
    merged = {}
    for t, v in pts:
        merged[round(t / T, 4)] = v
    keys = sorted(merged)
    if keys[0] != 0:
        raise ValueError("first change point must be at t=0")
    kt, vals = [], []
    for k in keys:
        if vals and vals[-1] == merged[k]:
            continue
        kt.append(f"{k:.4f}")
        vals.append(str(merged[k]))
    return (f'<animate attributeName="{attr}" dur="{T:.2f}s" repeatCount="indefinite" '
            f'calcMode="discrete" keyTimes="{";".join(kt)}" values="{";".join(vals)}"/>')


def fnv_ish(data):
    """The crackme's hash: FNV-1a 32 over the string *including* its NUL byte."""
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x1000193) & 0xffffffff
    return h


def cfg(ox, cx, oy):
    """radare2 VV-style control flow graph with a live execution trace.

    Two runs of a tiny crackme: a wrong key falls into .nope, then the right
    key ("r2") reaches .ok. Register values are actually computed.
    """
    FS, CW, LH, G = 9, 5.4, 10.5, 14
    STEP, EDGE_T, PAUSE = 0.22, 0.38, 1.2
    K = fnv_ish(b"r2\0")
    code = {
        "A": ("[0x1149] main", [(0x1149, "mov", "rsi, [rsi+8]"), (0x114d, "mov", "eax, 0x811c9dc5"),
                                (0x1152, "xor", "ecx, ecx")]),
        "C": ("[0x1154]", [(0x1154, "movzx", "edx, byte [rsi+rcx]"), (0x1158, "xor", "eax, edx"),
                           (0x115a, "imul", "eax, eax, 0x1000193"), (0x1160, "inc", "rcx"),
                           (0x1163, "test", "dl, dl"), (0x1165, "jnz", "0x1154")]),
        "D": ("[0x1167]", [(0x1167, "cmp", f"eax, 0x{K:08x}"), (0x116c, "jne", "0x1180")]),
        "E": ("[0x116e] .ok", [(0x116e, "lea", "rdi, [str.ok]"), (0x1175, "call", "sym.imp.puts")]),
        "F": ("[0x1180] .nope", [(0x1180, "lea", "rdi, [str.nope]"), (0x1187, "call", "sym.imp.puts")]),
    }
    # geometry
    box = {}
    def width(b):
        hdr, ins = code[b]
        return max(len(hdr), max(6 + len(o) for _, _, o in ins)) * CW + 16
    def height(b):
        return 15 + len(code[b][1]) * LH + 6
    y = oy
    for b in "ACD":
        w = width(b)
        box[b] = (cx - w / 2, y, w, height(b))
        y += height(b) + G
    wE, wF = width("E"), width("F")
    box["E"] = (cx - 8 - wE, y, wE, height("E"))
    box["F"] = (cx + 8, y, wF, height("F"))
    bottom = y + height("E")

    def bx(b): x, y, w, h = box[b]; return x, y, w, h
    def top(b): return box[b][1]
    def bot(b): return box[b][1] + box[b][3]
    def mid(b): return box[b][0] + box[b][2] / 2
    xA, yA, wA, hA = bx("C")
    edges = {  # key: (points, style)
        "AC": ([(cx, bot("A")), (cx, top("C"))], "u"),
        "CC": ([(cx + 34, bot("C")), (cx + 34, bot("C") + 6), (xA + wA + 12, bot("C") + 6),
                (xA + wA + 12, top("C") - 6), (cx + 34, top("C") - 6), (cx + 34, top("C"))], "t"),
        "CD": ([(cx - 20, bot("C")), (cx - 20, top("D"))], "f"),
        "DE": ([(cx - 24, bot("D")), (cx - 24, bot("D") + 7), (mid("E"), bot("D") + 7), (mid("E"), top("E"))], "f"),
        "DF": ([(cx + 24, bot("D")), (cx + 24, bot("D") + 7), (mid("F"), bot("D") + 7), (mid("F"), top("F"))], "t"),
    }
    def pathd(pts):
        return "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)

    # simulate two runs and build the timeline
    steps, trips, frames = [], [], {b: [(0, "#303030")] for b in code}
    t = 0.0
    for key, want in ((b"aa", "F"), (b"r2", "E")):
        data = key + b"\0"
        st = {"eax": 0x2, "rcx": 0, "edx": 0, "zf": 0}
        def regs():
            return f'eax {st["eax"]:08x}  rcx {st["rcx"]:x}  edx {st["edx"]:02x}  zf {st["zf"]}'
        def run_block(b, effects):
            nonlocal t
            frames[b].append((t, "#a0a0a0"))
            for i, fx in enumerate(effects):
                steps.append((t, b, i, regs(), code[b][1][i][0]))
                fx()
                t += STEP
        def go(e, src, dst):
            nonlocal t
            frames[src].append((t, "#303030"))
            trips.append((t, t + EDGE_T, e))
            t += EDGE_T
        def setv(**kw):
            return lambda: st.update(kw)
        run_block("A", [lambda: None, setv(eax=0x811c9dc5), setv(rcx=0, zf=1)])
        go("AC", "A", "C")
        while True:
            run_block("C", [
                lambda: st.update(edx=data[st["rcx"]]),
                lambda: st.update(eax=st["eax"] ^ st["edx"], zf=int((st["eax"] ^ st["edx"]) == 0)),
                lambda: st.update(eax=(st["eax"] * 0x1000193) & 0xffffffff),
                lambda: st.update(rcx=st["rcx"] + 1, zf=0),
                lambda: st.update(zf=int(st["edx"] == 0)),
                lambda: None])
            if st["zf"] == 0:
                go("CC", "C", "C")
            else:
                go("CD", "C", "D")
                break
        run_block("D", [lambda: st.update(zf=int(st["eax"] == K)), lambda: None])
        dst = "F" if st["zf"] == 0 else "E"
        assert dst == want, (key, dst)
        go("D" + dst, "D", dst)
        run_block(dst, [lambda: None, lambda: None])
        t += PAUSE
        frames[dst].append((t, "#303030"))
    T = t

    o = ['<defs>']
    for name, col in (("u", "#404040"), ("t", "#808080"), ("f", "#606060")):
        o.append(f'<marker id="ar{name}" viewBox="0 0 6 6" refX="5" refY="3" markerWidth="6" markerHeight="6" '
                 f'markerUnits="userSpaceOnUse" orient="auto"><path d="M0,0L6,3L0,6z" fill="{col}"/></marker>')
    o.append('</defs>')
    style = {"u": 'stroke="#404040"', "t": 'stroke="#808080"', "f": 'stroke="#606060" stroke-dasharray="3 2"'}
    for k, (pts, s) in edges.items():
        o.append(f'<path d="{pathd(pts)}" fill="none" stroke-width="1" {style[s]} marker-end="url(#ar{s})"/>')
    for b in code:
        x, y, w, h = box[b]
        o.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="#0b0b0b"/>')
    # instruction cursor (like the r2/binja highlighted line)
    def line_y(b, i):
        return box[b][1] + 15 + 3 + i * LH
    hp = {"x": [], "y": [], "width": [], "opacity": []}
    for (ts, b, i, _, _) in steps:
        x, _, w, _ = box[b]
        hp["x"].append((ts, f"{x+1:.1f}")); hp["y"].append((ts, f"{line_y(b, i):.1f}"))
        hp["width"].append((ts, f"{w-2:.1f}")); hp["opacity"].append((ts, 1))
    for (t0, _, _) in trips:
        hp["opacity"].append((t0, 0))
    b0 = steps[0][1]
    o.append(f'<rect x="{box[b0][0]+1:.1f}" y="{line_y(b0, 0):.1f}" width="{box[b0][2]-2:.1f}" height="{LH:.1f}" fill="#262626">'
             + "".join(disc(a, sorted(v, key=lambda p: p[0]), T) for a, v in hp.items()) + '</rect>')
    for b, (hdr, ins) in code.items():
        x, y, w, h = box[b]
        o.append(f'<text x="{x+8:.1f}" y="{y+11:.1f}" font-size="{FS}" fill="#707070">{esc(hdr)}</text>')
        o.append(f'<rect x="{x:.1f}" y="{y+15:.1f}" width="{w:.1f}" height="1" fill="#202020"/>')
        for i, (_, mn, ops) in enumerate(ins):
            by = line_y(b, i) + 8
            o.append(f'<text y="{by:.1f}" font-size="{FS}"><tspan x="{x+8:.1f}" fill="#cfcfcf">{mn}</tspan>'
                     f'<tspan x="{x+8+6*CW:.1f}" fill="#808080">{esc(ops)}</tspan></text>')
    for b in code:
        x, y, w, h = box[b]
        o.append(f'<rect x="{x+.5:.1f}" y="{y+.5:.1f}" width="{w-1:.1f}" height="{h-1:.1f}" fill="none" stroke="#303030">'
                 + disc("stroke", sorted(frames[b], key=lambda p: p[0]), T) + '</rect>')
    # the instruction pointer travelling along taken edges
    for (t0, t1, e) in trips:
        a, z = t0 / T, t1 / T
        o.append(f'<circle r="2.2" fill="#ffffff" opacity="0">'
                 f'<animateMotion dur="{T:.2f}s" repeatCount="indefinite" path="{pathd(edges[e][0])}" '
                 f'calcMode="linear" keyPoints="0;0;1;1" keyTimes="0;{a:.4f};{z:.4f};1"/>'
                 + disc("opacity", [(0, 0), (t0, 1), (t1, 0)], T) + '</circle>')
    # r2 prompt (seek follows the cursor) and a register line, one frame per step
    for n, (ts, b, i, rg, addr) in enumerate(steps):
        tn = steps[n + 1][0] if n + 1 < len(steps) else T
        pts = [(0, 1 if ts == 0 else 0)] + ([(ts, 1)] if ts else []) + ([(tn, 0)] if tn < T else [])
        anim = disc("opacity", pts, T)
        first = 1 if n == 0 else 0
        o.append(f'<text x="{ox}" y="{oy-12}" font-size="11" fill="#606060" opacity="{first}">'
                 f'[<tspan fill="#a0a0a0">0x{addr:08x}</tspan>]&gt; VV @ main{anim}</text>')
        o.append(f'<text x="{ox}" y="{bottom+16:.1f}" font-size="{FS}" fill="#707070" opacity="{first}" xml:space="preserve">{rg}{anim}</text>')
    return "\n".join(o), bottom + 16


def esc(s):
    return html.escape(s, quote=False)


# Layout: wide pieces (hero, section strips, snake, graph) scale with the page;
# everything else is a TW-wide card. Two cards fit side by side in GitHub's
# desktop README column (~820px) and wrap to one column on phones, where they
# only shrink to ~80%, so text stays readable.
TW = 404
PAD = 24


def chip_flow(x0, y0, groups, right):
    """Chips that wrap inside [x0, right]; groups: (labels, fill, color, gap_before)."""
    out, x, y = [], x0, y0
    for labels, fill, color, gap in groups:
        if x > x0:  # every group starts its own line
            x, y = x0, y + 33
        for label in labels:
            w = len(label) * 8.4 + 16
            if x > x0 and x + w > right:
                x, y = x0, y + 33
            out.append(f'<rect x="{x:.0f}" y="{y}" width="{w:.0f}" height="26" fill="{fill}"/>'
                       f'<text x="{x+8:.0f}" y="{y+18}" font-size="14" fill="{color}">{esc(label)}</text>')
            x += w + 6
    return "".join(out), y + 26


ABOUT = ("I live in a terminal on Void Linux: runit, ZFS, a patched dwm and a monochrome "
         "LazyVim. Mostly I take binaries apart: crackmes, stripped ELFs, anything that "
         "ships without source. The tools I need, I write in C/C++.")


def about_cards():
    import textwrap
    b = [f'<text x="{PAD}" y="42" font-size="15" fill="{DIM}">$ cat ~/about</text>',
         f'<text x="{PAD}" y="80" font-size="26" font-weight="700" fill="{HI}">Linux Systems &amp;</text>',
         f'<text x="{PAD}" y="112" font-size="26" font-weight="700" fill="{HI}">Binary Analysis</text>',
         f'<text x="{PAD}" y="142" font-size="15" fill="{MID}">Computer Engineering</text>']
    y = 180
    for line in textwrap.wrap(ABOUT, 39):
        b.append(f'<text x="{PAD}" y="{y}" font-size="15" fill="{FG}">{esc(line)}</text>')
        y += 23
    y += 14
    for line in ("void · runit · zfs · dwm · neovim", "C · C++ · Go · Lua", "radare2 · binary ninja"):
        b.append(f'<text x="{PAD}" y="{y}" font-size="15" fill="{DIM}">{esc(line)}</text>')
        y += 23
    chips, cy = "", y - 10
    # the r2 graph, drawn in its own coordinates and scaled into the card
    s, lx, ly = 1.42, 127, 24                 # extents ~[0, 265] x [0, 306] before scaling
    graph, gb = cfg(ox=0, cx=lx, oy=ly)
    gw = 265 * s
    tx = (TW - gw) / 2
    h = int(max(cy + PAD, 20 + (gb + 4) * s + 20))
    g = f'<g transform="translate({tx:.1f},20) scale({s})">{graph}</g>'
    return panel(h, "\n".join(b), w=TW), panel(h, g, w=TW)


def strip(label, right=""):
    """Full-width section header. Drawn 640 wide so it scales ~1.3x on desktop
    and ~0.5x on phones, where 22px type still lands near 11px."""
    w = 640
    body = (f'<text x="26" y="34" font-size="20" fill="{DIM}">$ <tspan fill="{HI}">{esc(label)}</tspan></text>'
            f'<text x="{w-26}" y="33" font-size="16" fill="{DIM}" text-anchor="end">{esc(right)}</text>'
            f'<rect x="26" y="47" width="{w-52}" height="1" fill="{EDGE}"/>')
    return panel(52, body, w=w)


def project(num, name, lang, desc, delay):
    import textwrap
    body = [f'<text x="{PAD}" y="36" font-size="15" fill="{DIM}">{esc(num)}</text>',
            f'<text x="{PAD+36}" y="36" font-size="17" font-weight="700" fill="{HI}">{esc(name)}</text>',
            f'<text x="{TW-PAD}" y="36" font-size="15" fill="{DIM}" text-anchor="end">{esc(lang)}</text>']
    for k, line in enumerate(textwrap.wrap(desc, 39)[:2]):
        body.append(f'<text x="{PAD}" y="{64 + k * 22}" font-size="15" fill="{FG}">{esc(line)}</text>')
    return panel(104, "".join(body), w=TW)


def link(label, sub):
    body = (f'<text x="{PAD}" y="32" font-size="17" fill="{HI}">{esc(label)}</text>'
            f'<text x="{TW-PAD}" y="32" font-size="15" fill="{DIM}" text-anchor="end">{esc(sub)} →</text>')
    return panel(52, body, w=TW)


def header():
    import random
    random.seed(11)
    H = 200
    name = "BEDEAF"
    glyphs = "0123456789ABCDEF"  # the name is itself hex, so it decodes from hex digits
    fs, cw = 84, 50.4
    x0 = (W - len(name) * cw) / 2
    o = [f'<text x="{W/2}" y="44" font-size="22" fill="{DIM}" text-anchor="middle">'
         f'mov <tspan fill="{FG}">eax</tspan>, <tspan fill="{HI}">0x00BEDEAF</tspan></text>']
    # decode-style name: each letter cycles through hex digits once, then settles
    for i, ch in enumerate(name):
        x = x0 + i * cw
        start = 0.3 + i * 0.12
        for k, g in enumerate(random.choice(glyphs.replace(ch, "")) for _ in range(5)):
            o.append(f'<text x="{x:.1f}" y="124" font-size="{fs}" font-weight="700" fill="{DIM}" visibility="hidden">{esc(g)}'
                     f'<set attributeName="visibility" to="visible" begin="{start + k * 0.07:.2f}s" dur="0.07s"/></text>')
        o.append(f'<text x="{x:.1f}" y="124" font-size="{fs}" font-weight="700" fill="{HI}" visibility="hidden">{ch}'
                 f'<set attributeName="visibility" to="visible" begin="{start + 0.35:.2f}s" fill="freeze"/></text>')
    o.append(f'<rect x="{x0:.0f}" y="146" width="{len(name)*cw:.0f}" height="1" fill="{EDGE}"/>')
    o.append(f'<text x="{W/2}" y="180" font-size="20" letter-spacing="3" fill="{FG}" text-anchor="middle">'
             'LINUX SYSTEMS &amp; BINARY ANALYSIS</text>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">\n'
            + "\n".join(o) + "\n</svg>\n")


def upstream_prs():
    """Pull requests bedeaf opened in other people's repositories, through `gh`
    (GH_TOKEN in CI). On failure the last good copy in data/upstream.json is
    used, so a run without network never drops the section."""
    import json, os, re, subprocess
    path = "data/upstream.json"
    try:
        res = subprocess.run(["gh", "api", "-X", "GET", "search/issues", "-f",
                              "q=author:bedeaf type:pr -user:bedeaf", "-f", "per_page=100"],
                             capture_output=True, text=True, timeout=60, check=True)
        prs = []
        for it in json.loads(res.stdout)["items"]:
            merged = (it.get("pull_request") or {}).get("merged_at")
            if it["state"] != "open" and not merged:
                continue                      # closed without merge: not shown
            title = re.sub(r"\s*##[\w-]+\s*$", "", it["title"])   # radare2 changelog tag
            prs.append({"repo": "/".join(it["repository_url"].split("/")[-2:]), "number": it["number"],
                        "title": title, "url": it["html_url"], "merged": merged, "opened": it["created_at"]})
        prs.sort(key=lambda p: (p["merged"] is None, -int(re.sub(r"\D", "", p["merged"] or p["opened"]))))
        os.makedirs("data", exist_ok=True)
        open(path, "w").write(json.dumps(prs, indent=1) + "\n")
    except Exception as e:
        print(f"warning: GitHub fetch failed ({e}); using {path}")
        prs = json.load(open(path))
    return prs


def pr_card(p):
    import textwrap
    state = "merged" if p["merged"] else "open"
    body = [f'<text x="{PAD}" y="36" font-size="16" font-weight="700" fill="{HI}">{esc(p["repo"])}</text>',
            f'<text x="{TW-PAD}" y="36" font-size="15" text-anchor="end" fill="{DIM}">#{p["number"]} · '
            f'<tspan fill="{HI if p["merged"] else DIM}">{state}</tspan></text>']
    for k, line in enumerate(textwrap.wrap(p["title"], 39)[:2]):
        body.append(f'<text x="{PAD}" y="{64 + k * 22}" font-size="15" fill="{FG}">{esc(line)}</text>')
    return panel(104, "".join(body), w=TW)


PROJECTS = [
    ("gom", "C", "native Linux games, isolated: bwrap · landlock · seccomp"),
    ("ppwm", "C++", "patchable C++20 X11 wm: autotiling, bar, XEmbed tray"),
    ("linux-mentor", "C", "runnable Linux experiments in C, C++23, Go. weekly"),
    ("void-config", "sh", "void on a ThinkPad: runit, ZFS, nftables, measured"),
    ("nvim", "Lua", "LazyVim: project-aware builds, debugging, monochrome"),
]
GH = "https://github.com/bedeaf"
SNAKE = ('<picture><source media="(prefers-color-scheme: dark)" srcset="../output/snake-dark.svg">'
         '<img src="../output/snake-light.svg" width="100%" alt="contribution snake"></picture>')
GRAPH = "https://github-readme-activity-graph.vercel.app/graph?username=bedeaf&area=true&hide_border=true&radius=6"
GRAPH_DARK = GRAPH + "&bg_color=00000000&color=ffffff60&line=ffffffa0&point=ffffffcf&area_color=ffffff40"
GRAPH_LIGHT = GRAPH + "&bg_color=ffffff00&color=8d8d8d&line=505050&point=2f2f2f&area_color=b6b6b6"

if __name__ == "__main__":
    about, trace = about_cards()
    out = {"hero": header(), "about": about, "trace": trace,
           "blog": link("~/blog", "writeups"), "crackmes": link("~/crackmes", "linkola"),
           "projects": strip("ls ~/projects", f"{len(PROJECTS)} entries"),
           "activity": strip("git log --graph", "updated every 12h")}
    for i, (n, l, d) in enumerate(PROJECTS, 1):
        out[f"p-{n}"] = project(f"{i:02d}", n, l, d, i * 0.6)
    prs = upstream_prs()
    merged = sum(1 for p in prs if p["merged"])
    out["upstream"] = strip("git log upstream", f"{merged} merged · {len(prs) - merged} open")
    for p in prs:
        out[f"pr-{p['repo'].split('/')[1]}-{p['number']}"] = pr_card(p)

    # Content-hashed names: raw.githubusercontent caches for 5 min and browsers
    # keep stale copies longer, so every change must get a fresh URL.
    import glob, hashlib, os
    names = {}
    for k, v in out.items():
        for mode in ("dark", "light"):
            svg = recolor(v, mode)
            names[k, mode] = f"{k}-{mode}.{hashlib.sha256(svg.encode()).hexdigest()[:8]}.svg"
            open(f"assets/{names[k, mode]}", "w").write(svg)
    for old in glob.glob("assets/*.svg"):
        if os.path.basename(old) not in {n for n in names.values()}:
            os.remove(old)

    def pic(k, alt, wide=False):
        # wide pieces scale with the page; cards keep their own width (max 100%)
        w = ' width="100%"' if wide else ""
        return (f'<picture><source media="(prefers-color-scheme: dark)" srcset="assets/{names[k, "dark"]}">'
                f'<img src="assets/{names[k, "light"]}"{w} alt="{html.escape(alt)}"></picture>')

    def a(href, inner):
        return f'<a href="{href}">{inner}</a>'

    def row(*items, left=False):
        return ('<p>' if left else '<p align="center">') + " ".join(items) + "</p>"

    cards = [a(f"{GH}/{n}", pic(f"p-{n}", f"{n}: {d}")) for n, _, d in PROJECTS]
    rows = [
        row(pic("hero", "bedeaf (0x00BEDEAF): linux systems & binary analysis", wide=True)),
        row(pic("about", "Linux Systems & Binary Analysis. Computer Engineering. Reversing with "
                         "radare2, Binary Ninja and more; tools in C/C++."),
            pic("trace", "radare2 graph view tracing a tiny crackme")),
        row(a("https://bedeaf.pages.dev/", pic("blog", "blog")),
            a("https://crackmes.one/user/linkola", pic("crackmes", "crackmes.one"))),
        row(pic("projects", "projects", wide=True)),
        row(*cards, left=True),  # one flow: two per line on desktop, one on phones; odd one stays in column
        row(pic("upstream", "pull requests to other projects", wide=True)),
        row(*[a(p["url"], pic(f"pr-{p['repo'].split('/')[1]}-{p['number']}",
                              f"{p['repo']}#{p['number']} ({'merged' if p['merged'] else 'open'}): {p['title']}"))
              for p in prs], left=True),
        row(pic("activity", "activity", wide=True)),
        row(SNAKE),
    ]
    open("README.md", "w").write("\n\n".join(rows) + "\n")
