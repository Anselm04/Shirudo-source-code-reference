#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Documentation/figures/build.py -- draw each <name>.tex of this directory
# with LaTeX and dvisvgm into Documentation/images/<name>.svg, its colors
# the pages' variables and its ids its own, or with --check, without TeX,
# fail on an SVG that its source and this script no longer make.
#
#   Documentation/figures/build.py [--all] [<name>...]
#   Documentation/figures/build.py --check

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGES = HERE.parent / "images"
STYLE = HERE / "shirudo-figure.sty"

# Each role of shirudo-figure.sty by the light value it is drawn in: the
# variable the pages set for it, then its light and dark value for an SVG
# opened on its own.
ROLES = {
    "#171b22": ("ink", "#171b22", "#e4e8ee"),
    "#5d6675": ("muted", "#5d6675", "#9ba5b3"),
    "#8a93a0": ("line", "#8a93a0", "#8a93a0"),
    "#e2e6eb": ("grid", "#e2e6eb", "#262d37"),
    "#c3c9d1": ("axis", "#c3c9d1", "#39414c"),
    "#8b1e3f": ("accent", "#8b1e3f", "#e8899f"),
    "#2a78d6": ("s1", "#2a78d6", "#3987e5"),
    "#eb6834": ("s2", "#eb6834", "#d95926"),
    "#1baf7a": ("s3", "#1baf7a", "#199e70"),
    "#eda100": ("s4", "#eda100", "#c98500"),
    "#dde2e8": ("free", "#dde2e8", "#2f3640"),
    "#ffffff": ("on", "#ffffff", "#ffffff"),
}

STAMP = re.compile(r"<!-- Documentation/figures/([\w.-]+\.tex), sha256 ([0-9a-f]{64}) -->")


class FigureError(Exception):
    pass


def digest(source):
    h = hashlib.sha256()
    for part in (Path(__file__).resolve(), STYLE, source):
        h.update(part.read_bytes())
    return h.hexdigest()


# An SVG's <style> applies to the whole page it is written into, so every
# class it names starts with fig.
def style_block():
    light = []
    dark = []
    for role, lv, dv in ROLES.values():
        for prop, short in (("fill", "f"), ("stroke", "s")):
            light.append(".fig-%s-%s{%s:var(--fig-%s,%s)}" % (short, role, prop, role, lv))
            dark.append(".fig-%s-%s{%s:var(--fig-%s,%s)}" % (short, role, prop, role, dv))
    return ("<style>%s@media (prefers-color-scheme:dark){%s}</style>"
            % ("".join(light), "".join(dark)))


def classes_for(name, attrs):
    found = []

    def take(m):
        prop, value = m.group(1), m.group(2).lower()
        if value == "none":
            return m.group(0)
        if re.fullmatch(r"#[0-9a-f]{3}", value):
            value = "#" + "".join(c * 2 for c in value[1:])
        if value not in ROLES:
            raise FigureError("%s: %s='%s' is not a color of shirudo-figure.sty"
                              % (name, prop, value))
        found.append("fig-%s-%s" % ("f" if prop == "fill" else "s", ROLES[value][0]))
        return ""

    attrs = re.sub(r"\s(fill|stroke)='([^']*)'", take, attrs)
    if found:
        attrs += " class='%s'" % " ".join(found)
    return attrs


def rewrite(name, svg, stamp):
    svg = re.sub(r"<\?xml[^>]*\?>\s*", "", svg)
    svg = re.sub(r"<!--.*?-->\s*", "", svg, flags=re.S)
    if re.search(r"\sstyle='|\sclass='", svg):
        raise FigureError("%s: dvisvgm wrote a style or class this script "
                          "does not handle" % name)
    # Ids of one figure must not meet those of another on the same page.
    svg = re.sub(r"\sid='([^']+)'", lambda m: " id='%s-%s'" % (name, m.group(1)), svg)
    svg = re.sub(r"\sxlink:href='#([^']+)'", lambda m: " href='#%s-%s'" % (name, m.group(1)), svg)
    svg = re.sub(r"url\(#([^)]+)\)", lambda m: "url(#%s-%s)" % (name, m.group(1)), svg)
    svg = re.sub(r"\sxmlns:xlink='[^']*'", "", svg)

    def tag(m):
        return "<%s%s%s>" % (m.group(1), classes_for(name, m.group(2)), m.group(3))

    svg = re.sub(r"<([A-Za-z][\w:-]*)((?:\s[^<>]*?)?)(/?)>", tag, svg)

    def root(m):
        attrs = m.group(1)
        size = {}
        for dim in ("width", "height"):
            v = re.search(r"\s%s='([\d.]+)pt'" % dim, attrs)
            if not v:
                raise FigureError("%s: no %s in pt" % (name, dim))
            size[dim] = "%.1f" % (float(v.group(1)) * 4 / 3)
            attrs = attrs.replace(v.group(0), " %s='%s'" % (dim, size[dim]))
        attrs = re.sub(r"\sversion='[^']*'", "", attrs)
        # The default fill is ink, not black, should a glyph have no color.
        return "<svg%s class='fig fig-f-ink' role='img'>%s%s" % (attrs, stamp, style_block())

    svg, n = re.subn(r"<svg((?:\s[^<>]*?)?)>", root, svg, count=1)
    if not n:
        raise FigureError("%s: no svg element" % name)
    return svg.strip() + "\n"


def build(source):
    name = source.stem
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, TEXINPUTS="%s:" % HERE)
        latex = subprocess.run(
            ["latex", "-interaction=nonstopmode", "-halt-on-error",
             "-output-directory", tmp, source.name],
            cwd=HERE, env=env, capture_output=True, text=True)
        if latex.returncode:
            raise FigureError("%s: latex failed:\n%s" % (name, latex.stdout[-2000:]))
        out = Path(tmp) / (name + ".svg")
        dvi = subprocess.run(
            ["dvisvgm", "--no-fonts", "--bbox=papersize", "--precision=3",
             "--optimize", "--output=%s" % out, str(Path(tmp) / (name + ".dvi"))],
            cwd=HERE, env=env, capture_output=True, text=True)
        if dvi.returncode or not out.exists():
            raise FigureError("%s: dvisvgm failed:\n%s" % (name, dvi.stderr[-2000:]))
        svg = out.read_text()
    stamp = "<!-- Documentation/figures/%s, sha256 %s -->" % (source.name, digest(source))
    (IMAGES / (name + ".svg")).write_text(rewrite(name, svg, stamp))


def recorded(svg):
    m = STAMP.search(svg.read_text()) if svg.exists() else None
    return m.group(2) if m else None


def check():
    bad = []
    for svg in sorted(IMAGES.glob("*.svg")):
        source = HERE / (svg.stem + ".tex")
        if not source.exists():
            bad.append("%s has no source %s" % (svg.relative_to(HERE.parent),
                                                 source.relative_to(HERE.parent)))
        elif recorded(svg) != digest(source):
            bad.append("%s is not what %s makes; run make -C Documentation figures"
                       % (svg.relative_to(HERE.parent), source.relative_to(HERE.parent)))
    for source in sorted(HERE.glob("*.tex")):
        if not (IMAGES / (source.stem + ".svg")).exists():
            bad.append("%s has no SVG; run make -C Documentation figures"
                       % source.relative_to(HERE.parent))
    for line in bad:
        print("figures: %s" % line, file=sys.stderr)
    return 1 if bad else 0


def main(argv):
    if argv == ["--check"]:
        return check()
    every = "--all" in argv
    names = [a for a in argv if a != "--all"]
    sources = [HERE / (n + ".tex") for n in names] or sorted(HERE.glob("*.tex"))
    built = 0
    for source in sources:
        if not source.exists():
            raise FigureError("no %s" % source)
        svg = IMAGES / (source.stem + ".svg")
        if names or every or recorded(svg) != digest(source):
            build(source)
            built += 1
            print("  FIGURE  %s" % svg.relative_to(HERE.parent))
    if not built:
        print("figures: every SVG is up to date")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except FigureError as e:
        print("figures: %s" % e, file=sys.stderr)
        sys.exit(1)
