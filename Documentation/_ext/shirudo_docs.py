# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Sphinx extension for the shirudo documentation: the page type and
# reader line under each title, the source and last change in the page
# footer, console blocks whose prompts name the role a command runs in,
# :src: links to the files of the repository, the figures of images/
# written into the page, so that they take the colors of its theme, and
# literals in tables that break after punctuation.

import html
import os
import re

from docutils import nodes
from pygments.lexer import RegexLexer, bygroups, default, using
from pygments.lexers.shell import BashLexer
from pygments.token import Generic, Whitespace
from sphinx.util.nodes import split_explicit_title


# "operator$ " runs on the operator host, "target# " as root on a target,
# "$ " and "# " anywhere. A backslash at the end continues the command.
class ConsoleLexer(RegexLexer):

    name = "shirudo console"
    aliases = ["console", "shell-session"]
    tokens = {
        "root": [
            (r"^(operator\$|target#|\$|#)( )",
             bygroups(Generic.Prompt, Whitespace), "command"),
            (r"[^\n]*\n", Generic.Output),
            (r"[^\n]+", Generic.Output),
        ],
        "command": [
            (r"[^\n]*\\\n", using(BashLexer)),
            (r"[^\n]*\n", using(BashLexer), "#pop"),
            (r"[^\n]+", using(BashLexer), "#pop"),
            default("#pop"),
        ],
    }


def meta_line(app, doctree, docname):
    meta = app.env.metadata.get(docname, {})
    parts = [meta.get(key) for key in ("page-type", "audience")]
    parts = [part for part in parts if part]
    if not parts:
        return
    for section in doctree.findall(nodes.section):
        title = section.next_node(nodes.title)
        if title is not None:
            line = nodes.paragraph("", " · ".join(parts), classes=["meta"])
            title.parent.insert(title.parent.index(title) + 1, line)
        return


def inline_figures(app, doctree, docname):
    """An <img> sees neither the page's variables nor its data-theme, so a
    figure of images/ goes into the page as its SVG, labeled with its alt."""
    if app.builder.format != "html":
        return
    for image in list(doctree.findall(nodes.image)):
        uri = image["uri"]
        if not (uri.startswith("images/") and uri.endswith(".svg")):
            continue
        with open(os.path.join(app.srcdir, uri), encoding="utf-8") as f:
            svg = f.read()
        label = " aria-label='%s'" % html.escape(image.get("alt", ""), quote=True)
        svg = svg.replace(" role='img'", " role='img'" + label, 1)
        image.replace_self(nodes.raw("", svg, format="html"))


# The theme keeps every word of a literal on one line, so a path, option
# or setting in a table cell would set the width of its column alone.
# <wbr> adds no character, so a copied literal stays the same.
TABLE_BREAK = re.compile(r"(?<=[^/._\-=,:|\s])[/._\-=,:|]+(?=[^/._\-=,:|\s])")


def break_table_literals(app, doctree, docname):
    """Let a literal in a table cell break after / . _ - = , : | and
    nowhere else."""
    if app.builder.format != "html":
        return
    for entry in doctree.findall(nodes.entry):
        for literal in list(entry.findall(nodes.literal)):
            if "kbd" in literal["classes"] or literal.get("language"):
                continue
            for text in list(literal.findall(nodes.Text)):
                value = str(text)
                parts = []
                start = 0
                for match in TABLE_BREAK.finditer(value):
                    parts.append(nodes.Text(value[start:match.end()]))
                    parts.append(nodes.raw("", "<wbr>", format="html"))
                    start = match.end()
                if parts:
                    parts.append(nodes.Text(value[start:]))
                    text.parent.replace(text, parts)


CHANGES = {}


def last_changes():
    path = os.environ.get("DOCS_LASTCHANGE")
    changes = {}
    if not path or not os.path.exists(path):
        return changes
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            fields = line.rstrip("\n").split("\t")
            if len(fields) == 3 and fields[0]:
                changes[fields[0]] = (fields[1], fields[2])
    return changes


def page_context(app, pagename, templatename, context, doctree):
    if doctree is None:
        return
    source = "Documentation/" + pagename + ".rst"
    context["source_file"] = source
    context["last_change"], context["last_change_date"] = \
        CHANGES.get(source, (None, None))
    context["github_url"] = "%s/blob/%s/%s" % (
        context.get("repository"), context.get("branch"), source)


def first_paragraph(doctree, limit=300):
    for para in doctree.findall(nodes.paragraph):
        if {"meta", "etymology"} & set(para.get("classes", [])):
            continue
        text = " ".join(para.astext().split())
        if len(text) > limit:
            cut = text.rfind(". ", 0, limit)
            text = text[:cut + 1] if cut > 0 else text[:limit] + "..."
        return text
    return ""


def toctree_walk(env, docname):
    yield docname
    for child in env.toctree_includes.get(docname, []):
        yield from toctree_walk(env, child)


# llms.txt: an index of the plain-text pages for readers that are agents.
def write_llms(app, exception):
    if exception is not None or app.builder.name != "html":
        return
    env = app.env
    root = app.config.root_doc
    lines = ["# shirudo documentation", ""]
    intro = first_paragraph(env.get_doctree(root), 1000)
    if intro:
        lines += ["> " + intro, ""]
    lines += ["Every page below is plain text; the HTML version has the "
              "same path without _text/ and with .html.", ""]
    for section in env.toctree_includes.get(root, []):
        lines += ["## " + env.titles[section].astext(), ""]
        for docname in toctree_walk(env, section):
            title = env.titles[docname].astext()
            desc = first_paragraph(env.get_doctree(docname))
            entry = "- [%s](_text/%s.txt)" % (title, docname)
            lines.append(entry + (": " + desc if desc else ""))
        lines.append("")
    path = os.path.join(app.outdir, "llms.txt")
    with open(path, "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


# :src:`path` shows a path of the repository as code and links it on
# GitHub, and :src:`title <path>` shows the title instead. A path the
# checkout does not have is reported, so that a file moved or removed
# cannot leave a dead link behind.
def src_role(name, rawtext, text, lineno, inliner, options=None,
             content=None):
    env = inliner.document.settings.env
    context = env.config.html_context
    _, title, path = split_explicit_title(text.strip())
    local = os.path.join(os.path.dirname(os.path.abspath(env.srcdir)),
                         path.rstrip("/"))
    messages = []
    if not os.path.exists(local):
        messages.append(inliner.reporter.warning(
            "src: %s is not in the repository" % path, line=lineno))
    kind = "tree" if os.path.isdir(local) else "blob"
    url = "%s/%s/%s/%s" % (context["repository"], kind, context["branch"],
                           path)
    node = nodes.reference(rawtext, "", refuri=url)
    node += nodes.literal(title, title)
    return [node], messages


def setup(app):
    app.add_role("src", src_role)
    app.add_lexer("console", ConsoleLexer)
    app.add_lexer("shell-session", ConsoleLexer)
    CHANGES.update(last_changes())
    app.connect("doctree-resolved", meta_line)
    app.connect("doctree-resolved", inline_figures)
    app.connect("doctree-resolved", break_table_literals)
    app.connect("html-page-context", page_context)
    app.connect("build-finished", write_llms)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
