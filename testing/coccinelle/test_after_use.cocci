// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A pointer dereferenced, or handed to a function that takes no NULL,
// before the test that it may be NULL: the test comes too late.

virtual report

@initialize:python@
@@
unevaluated = set()

@ufld@
attribute name SEC;
expression E, B;
identifier fld;
position p;
@@
(
  sizeof(<+... E->fld@p ...+>)
|
  E ? <+... E->fld@p ...+> : B
|
  !E || <+... E->fld@p ...+>
|
  E && <+... E->fld@p ...+>
|
  E == NULL || <+... E->fld@p ...+>
|
  E != NULL && <+... E->fld@p ...+>
)

@script:python@
p << ufld.p;
@@
unevaluated.add((p[0].file, p[0].line, p[0].column))

@uptr@
expression E, B;
position p;
@@
(
  sizeof(<+... *E@p ...+>)
|
  E ? <+... *E@p ...+> : B
|
  !E || <+... *E@p ...+>
|
  E && <+... *E@p ...+>
|
  E == NULL || <+... *E@p ...+>
|
  E != NULL && <+... *E@p ...+>
)

@script:python@
p << uptr.p;
@@
unevaluated.add((p[0].file, p[0].line, p[0].column))

@ufn@
expression E, B;
identifier f = {strlen, strnlen, strcmp, strncmp, strchr, strrchr, strstr,
		strcasecmp, strncasecmp, strspn, strcspn, memchr, strscpy};
position p;
@@
(
  E ? <+... f@p(..., E, ...) ...+> : B
|
  !E || <+... f@p(..., E, ...) ...+>
|
  E && <+... f@p(..., E, ...) ...+>
|
  E == NULL || <+... f@p(..., E, ...) ...+>
|
  E != NULL && <+... f@p(..., E, ...) ...+>
)

@script:python@
p << ufn.p;
@@
unevaluated.add((p[0].file, p[0].line, p[0].column))

@r exists@
expression E, E1;
identifier fld;
identifier f = {strlen, strnlen, strcmp, strncmp, strchr, strrchr, strstr,
		strcasecmp, strncasecmp, strspn, strcspn, memchr, strscpy};
position p1, p2;
@@
(
  E->fld@p1
|
  *E@p1
|
  f@p1(..., E, ...)
)
  ... when != E = E1
      when != &E
      when != E++
      when != E--
      when != E += E1
(
  !E@p2
|
  E@p2 == NULL
|
  NULL == E@p2
|
  E@p2 != NULL
)

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
E << r.E;
@@
import re
# Within one statement, as in a ternary, the order is not the one of
# execution, and a loop tests again what its previous turn used. A test
# after a label is for the paths that come there before the use, a use
# that assigns the pointer is followed by a test of the new value, and
# a use in a block that an if or a loop on the pointer opens, or after
# a test of it in its own block, is guarded by them.
def indent(l):
    return len(l.expandtabs(8)) - len(l.expandtabs(8).lstrip())
lines = open(p1[0].file).read().split("\n")
use, test = int(p1[0].line), int(p2[0].line)
name = re.escape(E)
tested = re.compile(r"(!\s*\(?\s*%s\b|\b%s\s*[!=]=\s*NULL)" % (name, name))
opener = re.compile(r"^\s*(if|while|for|else|do)\b|\{\s*$")
label = any(re.match(r"^[A-Za-z_]\w*:\s*$", l) for l in lines[use:test - 1])
reassigned = re.search(r"(^|[^=!<>])\b%s\s*=[^=]" % name, lines[use - 1]) is not None
guard = False
level = indent(lines[use - 1])
for l in reversed(lines[:use - 1]):
    if not l.strip():
        continue
    if indent(l) >= level:
        if tested.search(l) and indent(l) == level:
            guard = True
            break
        continue
    if not opener.search(l):
        continue
    if re.search(r"\b(if|while|for)\b.*\b%s\b" % name, l):
        guard = True
        break
    level = indent(l)
    if level == 0:
        break
if use < test and not label and not reassigned and not guard and \
   (p1[0].file, p1[0].line, p1[0].column) not in unevaluated:
    coccilib.report.print_report(p2[0], "%s is tested for NULL after its use at line %s" % (E, p1[0].line))
