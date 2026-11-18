#!/usr/bin/env python3
"""Generate the black SVG panels used by README.md (run from repo root)."""
import re, html

FONT = "'Liberation Mono',Menlo,Consolas,monospace"
W = 900
BG, FG, DIM, MID, HI, EDGE = "#000000", "#a0a0a0", "#606060", "#808080", "#cfcfcf", "#202020"


def panel(h, body, extra_style=""):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}" '
            f'font-family="{FONT}">\n<style>{extra_style}</style>\n'
            f'<rect width="{W}" height="{h}" rx="6" fill="{BG}"/>\n'
            f'<rect x=".5" y=".5" width="{W-1}" height="{h-1}" rx="6" fill="none" stroke="{EDGE}"/>\n'
            f'{body}\n</svg>\n')


def esc(s):
    return html.escape(s, quote=False)


def chips(x, y, items, fill, color):
    out = []
    for label in items:
        w = len(label) * 7.8 + 18
        out.append(f'<rect x="{x}" y="{y}" width="{w:.0f}" height="24" fill="{fill}"/>'
                   f'<text x="{x+9}" y="{y+16.5}" font-size="13" fill="{color}">{esc(label)}</text>')
        x += w + 6
    return "".join(out), x


def about():
    net = open("assets/network.svg").read()
    net = net.replace("path{", ".net path{").replace("circle{", ".net circle{")
    grays = {"#7c8798": "#606060", "#8a96a6": "#707070", "#b4bfcd": "#a0a0a0",
             "#bcc5d1": "#afafaf", "#d0d6df": "#cfcfcf"}
    for a, b in grays.items():
        net = net.replace(a, b)
    net = re.sub(r'<svg [^>]*>', '<svg class="net" x="680" y="22" width="200" height="200" viewBox="0 0 200 200">', net, count=1)
    b = [f'<text x="28" y="50" font-size="13" fill="{DIM}">$ cat ~/about</text>',
         f'<text x="28" y="88" font-size="26" font-weight="700" fill="{HI}">Linux Systems &amp;</text>',
         f'<text x="28" y="120" font-size="26" font-weight="700" fill="{HI}">Network Engineering</text>',
         f'<text x="28" y="150" font-size="14" fill="{MID}">Computer Engineering</text>',
         f'<text x="28" y="182" font-size="14" fill="{FG}">I live in a terminal on Void Linux: runit, ZFS, a patched dwm</text>',
         f'<text x="28" y="202" font-size="14" fill="{FG}">and a monochrome LazyVim. I build sandboxes, window managers</text>',
         f'<text x="28" y="222" font-size="14" fill="{FG}">and small sharp tools in C/C++, and live inside Linux internals,</text>',
         f'<text x="28" y="242" font-size="14" fill="{FG}">networking and disassemblers.</text>']
    c1, _ = chips(28, 266, ["void", "runit", "zfs", "dwm", "neovim", "urxvt"], "#202020", FG)
    c2, x = chips(28, 298, ["C", "C++", "Go", "Lua"], "#404040", HI)
    c3, _ = chips(x + 8, 298, ["reversing:", "radare2", "binary ninja", "more"], "#171717", FG)
    return panel(342, "\n".join(b) + c1 + c2 + c3 + net)


def strip(label, right=""):
    body = (f'<text x="28" y="30" font-size="14" fill="{DIM}">$ <tspan fill="{HI}">{esc(label)}</tspan></text>'
            f'<text x="{W-28}" y="30" font-size="13" fill="{DIM}" text-anchor="end">{esc(right)}</text>')
    return panel(48, body)


def project(i, name, lang, desc):
    body = (f'<text x="28" y="34" font-size="13" fill="{DIM}">{i:02d}</text>'
            f'<text x="66" y="34" font-size="17" font-weight="700" fill="{HI}">{esc(name)}</text>'
            f'<text x="232" y="34" font-size="14" fill="{FG}">{esc(desc)}</text>'
            f'<rect x="{W-86}" y="17" width="58" height="22" fill="#202020"/>'
            f'<text x="{W-57}" y="32.5" font-size="12" fill="{MID}" text-anchor="middle">{esc(lang)}</text>'
            f'<rect class="u" x="66" y="42" width="0" height="2" fill="{FG}"/>')
    css = ".u{animation:u 5s ease-in-out %ss infinite}@keyframes u{0%%,60%%{width:0}75%%,90%%{width:120px}100%%{width:0}}" % (i * 0.6)
    return panel(56, body, css)


def link(label, sub):
    w = W // 2 - 3
    body = (f'<text x="28" y="30" font-size="15" fill="{HI}">{esc(label)}</text>'
            f'<text x="{w-24}" y="30" font-size="13" fill="{DIM}" text-anchor="end">{esc(sub)} →</text>')
    return (panel(48, body).replace(f'width="{W}" height="48" viewBox="0 0 {W} 48"', f'width="{w}" height="48" viewBox="0 0 {w} 48"')
            .replace(f'width="{W}" height="48" rx', f'width="{w}" height="48" rx')
            .replace(f'width="{W-1}" height="47"', f'width="{w-1}" height="47"'))


PROJECTS = [
    ("gom", "C", "untrusted Linux games in a bwrap·landlock·seccomp cage"),
    ("ppwm", "C++", "patchable C++20 X11 wm: autotiling, bar, XEmbed tray"),
    ("linux-mentor", "C", "runnable Linux experiments in C, C++23, Go. weekly"),
    ("void-config", "sh", "void on a ThinkPad: runit, ZFS, nftables, measured"),
    ("nvim", "Lua", "LazyVim: project-aware builds, debugging, monochrome"),
]

if __name__ == "__main__":
    out = {"about": about(), "projects": strip("ls ~/projects", f"{len(PROJECTS)} entries"),
           "activity": strip("git log --graph", "updated every 12h"),
           "blog": link("~/blog", "writeups"), "linkedin": link("~/linkedin", "in/***")}
    for i, (n, l, d) in enumerate(PROJECTS, 1):
        out[f"p-{n}"] = project(i, n, l, d)
    for k, v in out.items():
        open(f"assets/{k}.svg", "w").write(v)
