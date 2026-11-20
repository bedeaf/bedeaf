#!/usr/bin/env python3
"""Recolor a gray-palette SVG for GitHub's dark and light themes.

Everything is drawn once in the black / #a0a0a0 ramp, with no background.

dark:  each gray #vvvvvv becomes white at alpha vv. On pure black that is
       the original color; on GitHub's #0d1117 or #212830 pages every element
       lifts by the same amount, so boxes stay lighter than the page.
light: every light theme is white, so each gray becomes the solid gray with
       the same contrast against white that it had against black.

usage: theme.py IN.svg DARK.svg LIGHT.svg
"""
import re
import sys

# #vvvvvv or #vvv, not part of a longer hex run, not an &#NNN; entity
GRAY = re.compile(r"(?<!&)#(?:([0-9a-fA-F]{2})\1\1|([0-9a-fA-F])\2\2)(?![0-9a-fA-F])")


def _lin(v):
    c = v / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _srgb(lum):
    c = 12.92 * lum if lum <= 0.0031308 else 1.055 * lum ** (1 / 2.4) - 0.055
    return max(0, min(255, round(c * 255)))


def light_level(v):
    """Gray level whose contrast on white equals that of level v on black."""
    ratio = (_lin(v) + 0.05) / 0.05
    return _srgb(1.05 / ratio - 0.05)


def _level(m):
    return int(m.group(1), 16) if m.group(1) else int(m.group(2) * 2, 16)


def recolor(svg, mode):
    if mode == "dark":
        def sub(m):
            v = _level(m)
            return "#ffffff" if v == 255 else f"#ffffff{v:02x}"
    elif mode == "light":
        def sub(m):
            return "#" + f"{light_level(_level(m)):02x}" * 3
    else:
        raise ValueError(mode)
    return GRAY.sub(sub, svg)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__.rsplit("\n\n", 1)[1])
    src = open(sys.argv[1]).read()
    for path, mode in ((sys.argv[2], "dark"), (sys.argv[3], "light")):
        open(path, "w").write(recolor(src, mode))
