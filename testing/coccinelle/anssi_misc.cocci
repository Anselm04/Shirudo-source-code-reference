// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Constructs the tree does without: a bitwise operator on a bool, a
// comma that sequences statements, a goto that jumps backwards, a
// floating-point loop counter, and a variadic call passed a bare NULL,
// which is an int where NULL is 0.

virtual report

@bitbool@
attribute name SEC;
bool A;
expression B;
binary operator op = {&, |, ^};
position p;
@@
(
  A op@p B
|
  B op@p A
)

@script:python depends on report@
p << bitbool.p;
@@
coccilib.report.print_report(p[0], "a bitwise operator on a bool; use && or ||")

@comma@
expression E1, E2;
position p;
@@
  E1 ,@p E2;

@script:python depends on report@
p << comma.p;
@@
coccilib.report.print_report(p[0], "a comma sequencing statements")

@backward exists@
identifier l;
position p;
@@
l:
  ...
  goto@p l;

@script:python depends on report@
p << backward.p;
l << backward.l;
@@
import re
# A path back to the label through a loop is no backward goto; one
# whose label stands above it in the function is.
lines = open(p[0].file).read().split("\n")[:int(p[0].line) - 1]
if any(re.match(r"^%s:\s*$" % re.escape(l), x) for x in lines[::-1]
       [:next((i for i, x in enumerate(lines[::-1]) if x.startswith("}")), len(lines))]):
    coccilib.report.print_report(p[0], "a goto that jumps backwards; write the loop")

@floatloop@
{float, double} X;
expression E1, E2, E3;
statement S;
position p;
@@
  for@p (X = E1; E2; E3) S

@script:python depends on report@
p << floatloop.p;
@@
coccilib.report.print_report(p[0], "a floating-point loop counter")

@varnull@
identifier f = {printf, fprintf, dprintf, pr_err, pr_warn, pr_info,
		pr_debug, pr_audit, pr_hint, strsprintf, xasprintf, execl,
		execlp, execle};
position p;
@@
  f@p(..., NULL, ...)

@script:python depends on report@
p << varnull.p;
f << varnull.f;
@@
coccilib.report.print_report(p[0], "a bare NULL passed to %s(); cast it to the pointer type" % f)
