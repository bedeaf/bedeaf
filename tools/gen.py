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
FG, DIM, MID, HI, EDGE = "#a0a0a0", "#606060", "#808080", "#cfcfcf", "#202020"


def panel(h, body, extra_style="", w=W, inset=0):
    # inset: cards draw their frame 4px in, so neighbours keep a gap both
    # side by side (desktop) and stacked (phone)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'font-family="{FONT}">\n<style>{extra_style}</style>\n'
            f'<rect x="{inset+.5}" y="{inset+.5}" width="{w-1-2*inset}" height="{h-1-2*inset}" fill="none" stroke="{EDGE}"/>\n'
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
        if x > x0:
            x += gap
        for label in labels:
            w = len(label) * 7.8 + 18
            if x > x0 and x + w > right:
                x, y = x0, y + 30
            out.append(f'<rect x="{x:.0f}" y="{y}" width="{w:.0f}" height="24" fill="{fill}"/>'
                       f'<text x="{x+9:.0f}" y="{y+16.5}" font-size="13" fill="{color}">{esc(label)}</text>')
            x += w + 6
    return "".join(out), y + 24


ABOUT = ("I live in a terminal on Void Linux: runit, ZFS, a patched dwm and a monochrome "
         "LazyVim. Mostly I take binaries apart: crackmes, stripped ELFs, anything that "
         "ships without source. The tools I need, I write in C/C++.")


def about_cards():
    import textwrap
    b = [f'<text x="{PAD}" y="40" font-size="13" fill="{DIM}">$ cat ~/about</text>',
         f'<text x="{PAD}" y="78" font-size="26" font-weight="700" fill="{HI}">Linux Systems &amp;</text>',
         f'<text x="{PAD}" y="110" font-size="26" font-weight="700" fill="{HI}">Binary Analysis</text>',
         f'<text x="{PAD}" y="140" font-size="14" fill="{MID}">Computer Engineering</text>']
    y = 176
    for line in textwrap.wrap(ABOUT, 41):
        b.append(f'<text x="{PAD}" y="{y}" font-size="14" fill="{FG}">{esc(line)}</text>')
        y += 21
    chips, cy = chip_flow(PAD, y + 4, [
        (["void", "runit", "zfs", "dwm", "neovim", "urxvt"], "#202020", FG, 0),
        (["C", "C++", "Go", "Lua"], "#404040", HI, 14),
        (["reversing:", "radare2", "binary ninja", "more"], "#171717", FG, 14)], TW - PAD)
    # the r2 graph, drawn in its own coordinates and scaled into the card
    s, lx, ly = 1.3, 127, 24                  # extents ~[0, 265] x [0, 306] before scaling
    graph, gb = cfg(ox=0, cx=lx, oy=ly)
    gw = 265 * s
    tx = (TW - gw) / 2
    h = int(max(cy + PAD, 20 + (gb + 4) * s + 20))
    g = f'<g transform="translate({tx:.1f},20) scale({s})">{graph}</g>'
    return panel(h, "\n".join(b) + chips, w=TW, inset=4), panel(h, g, w=TW, inset=4)


def strip(label, right=""):
    """Full-width section header. Drawn 700 wide so it scales ~1.2x on desktop
    and ~0.47x on phones, where 22px type still lands near 10px."""
    w = 700
    body = (f'<text x="26" y="34" font-size="22" fill="{DIM}">$ <tspan fill="{HI}">{esc(label)}</tspan></text>'
            f'<text x="{w-26}" y="33" font-size="18" fill="{DIM}" text-anchor="end">{esc(right)}</text>')
    return panel(52, body, w=w)


def project(num, name, lang, desc, delay):
    import textwrap
    body = [f'<text x="{PAD}" y="36" font-size="13" fill="{DIM}">{esc(num)}</text>',
            f'<text x="{PAD+34}" y="36" font-size="17" font-weight="700" fill="{HI}">{esc(name)}</text>',
            f'<rect x="{TW-PAD-52}" y="20" width="52" height="22" fill="#202020"/>',
            f'<text x="{TW-PAD-26}" y="35.5" font-size="12" fill="{MID}" text-anchor="middle">{esc(lang)}</text>',
            f'<rect class="u" x="{PAD+34}" y="44" width="0" height="2" fill="{FG}"/>']
    for k, line in enumerate(textwrap.wrap(desc, 44)[:2]):
        body.append(f'<text x="{PAD}" y="{68 + k * 19}" font-size="13" fill="{FG}">{esc(line)}</text>')
    css = (".u{animation:u 5s ease-in-out %.1fs infinite}"
           "@keyframes u{0%%,60%%{width:0}75%%,90%%{width:%dpx}100%%{width:0}}" % (delay, round(len(name) * 10.2)))
    return panel(110, "".join(body), css, w=TW, inset=4)


def link(label, sub):
    body = (f'<text x="{PAD}" y="32" font-size="15" fill="{HI}">{esc(label)}</text>'
            f'<text x="{TW-PAD}" y="32" font-size="13" fill="{DIM}" text-anchor="end">{esc(sub)} →</text>')
    return panel(52, body, w=TW, inset=4)


def header():
    import random
    random.seed(11)
    H = 280
    name = "BEDEAF"
    glyphs = "0123456789ABCDEF"  # the name is itself hex, so it decodes from hex digits
    fs, cw = 84, 50.4
    x0 = (W - len(name) * cw) / 2
    o = []
    # gray ramp columns (eyes.nvim ramp) breathing in the back
    ramp = ["#0b0b0b", "#101010", "#171717", "#202020", "#303030"]
    for i in range(45):
        c = ramp[random.randrange(len(ramp))]
        h = random.randint(12, 40)
        d = random.uniform(3, 7)
        o.append(f'<rect x="{i*20}" y="{H-h}" width="19" height="{h}" fill="{c}">'
                 f'<animate attributeName="height" values="{h};{h*0.4:.0f};{h}" dur="{d:.1f}s" repeatCount="indefinite"/>'
                 f'<animate attributeName="y" values="{H-h};{H-h*0.4:.0f};{H-h}" dur="{d:.1f}s" repeatCount="indefinite"/></rect>')
    # the instruction that loads the name, shown first
    o.append(f'<text x="{W/2}" y="58" font-size="20" fill="{DIM}" text-anchor="middle" opacity="0">'
             f'mov <tspan fill="{FG}">eax</tspan>, <tspan fill="{HI}">0x00BEDEAF</tspan>'
             f'<animate attributeName="opacity" from="0" to="1" begin="0.1s" dur="0.6s" fill="freeze"/></text>')
    # decode-style name: each letter cycles through hex digits, then settles
    for i, ch in enumerate(name):
        x = x0 + i * cw
        start = 0.6 + i * 0.18
        seq = [random.choice(glyphs.replace(ch, "")) for _ in range(7)]
        for k, g in enumerate(seq):
            t = start + k * 0.07
            o.append(f'<text x="{x:.1f}" y="148" font-size="{fs}" font-weight="700" fill="{DIM}" visibility="hidden">{esc(g)}'
                     f'<set attributeName="visibility" to="visible" begin="{t:.2f}s" dur="0.07s"/></text>')
        o.append(f'<text x="{x:.1f}" y="148" font-size="{fs}" font-weight="700" fill="{HI}" visibility="hidden">{ch}'
                 f'<set attributeName="visibility" to="visible" begin="{start+0.49:.2f}s" fill="freeze"/></text>')
    end = 0.6 + len(name) * 0.18 + 0.5
    # rule, then the dword as it lands in memory (little-endian), byte by byte
    o.append(f'<rect x="{x0:.0f}" y="172" width="0" height="2" fill="{FG}"><animate attributeName="width" from="0" to="{len(name)*cw:.0f}" begin="{end:.2f}s" dur="0.8s" fill="freeze"/></rect>')
    gx = W / 2 - 131  # "[rsp]" + gap + four bytes, centred as one group
    o.append(f'<text x="{gx:.0f}" y="210" font-size="22" fill="{DIM}" opacity="0">[rsp]'
             f'<animate attributeName="opacity" from="0" to="1" begin="{end+0.8:.2f}s" dur="0.3s" fill="freeze"/></text>')
    for k, byte in enumerate(["af", "de", "be", "00"]):
        bx = gx + 86 + k * 48
        o.append(f'<text x="{bx:.0f}" y="210" font-size="26" fill="{HI if byte != "00" else FG}" opacity="0">{byte}'
                 f'<set attributeName="opacity" to="1" begin="{end+1.0+k*0.22:.2f}s" fill="freeze"/></text>')
    end += 1.0 + 4 * 0.22
    o.append(f'<text x="{W/2}" y="244" font-size="18" letter-spacing="3" fill="{FG}" text-anchor="middle" opacity="0">LINUX SYSTEMS &amp; BINARY ANALYSIS'
             f'<animate attributeName="opacity" from="0" to="1" begin="{end+0.2:.2f}s" dur="1s" fill="freeze"/></text>')
    # slow light sweep, like the hard light on the wallpaper
    o.append('<defs><linearGradient id="sw" x1="0" x2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/>'
             '<stop offset=".5" stop-color="#fff" stop-opacity=".06"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient></defs>')
    o.append(f'<rect x="-260" width="260" height="{H}" fill="url(#sw)"><animate attributeName="x" from="-260" to="{W}" dur="8s" begin="{end:.2f}s" repeatCount="indefinite"/></rect>')
    o.append(f'<rect x=".5" y=".5" width="{W-1}" height="{H-1}" fill="none" stroke="{EDGE}"/>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">\n'
            + "\n".join(o) + "\n</svg>\n")


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
           "activity": strip("git log --graph", "updated every 12h"),
           "more": project("··", "more", "all", "every repository, forks and upstream patches", 3.6)}
    for i, (n, l, d) in enumerate(PROJECTS, 1):
        out[f"p-{n}"] = project(f"{i:02d}", n, l, d, i * 0.6)

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

    def row(*items):
        return '<p align="center">' + " ".join(items) + "</p>"

    cards = [a(f"{GH}/{n}", pic(f"p-{n}", f"{n}: {d}")) for n, _, d in PROJECTS]
    cards.append(a(f"{GH}?tab=repositories", pic("more", "all repositories")))
    rows = [
        row(pic("hero", "bedeaf (0x00BEDEAF): linux systems & binary analysis", wide=True)),
        row(pic("about", "Linux Systems & Binary Analysis. Computer Engineering. Reversing with "
                         "radare2, Binary Ninja and more; tools in C/C++."),
            pic("trace", "radare2 graph view tracing a tiny crackme")),
        row(a("https://bedeaf.pages.dev/", pic("blog", "blog")),
            a("https://crackmes.one/user/linkola", pic("crackmes", "crackmes.one"))),
        row(pic("projects", "projects", wide=True)),
        row(*cards),  # one flow: two per line on desktop, one on phones
        row(pic("activity", "activity", wide=True)),
        row(SNAKE),
        row(f'<picture><source media="(prefers-color-scheme: dark)" srcset="{GRAPH_DARK}">'
            f'<img src="{GRAPH_LIGHT}" width="100%" alt="activity graph"></picture>'),
    ]
    open("README.md", "w").write("\n\n".join(rows) + "\n")
