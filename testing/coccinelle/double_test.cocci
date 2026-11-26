// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A condition that tests one term twice, an if or a conditional whose
// branches do the same, or an else if that tests what an if before it
// tested and so never runs, is a copy left in place of what was meant.

virtual report

@r@
attribute name SEC;
expression E;
position p;
@@
(
  E &&@p E
|
  E ||@p E
)

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "the same term tested twice")

@b@
expression E;
statement S;
position p;
@@
  if (E@p) S else S

@script:python depends on report@
p << b.p;
@@
coccilib.report.print_report(p[0], "both branches of the if do the same")

@t@
expression C, E;
position p;
@@
  C ?@p E : E

@script:python depends on report@
p << t.p;
@@
coccilib.report.print_report(p[0], "both branches of the conditional are alike")

@e@
expression C, C2;
statement S1, S2, S3, S4;
position p;
@@
(
  if (C) S1 else if (C@p) S2
|
  if (C) S1 else if (C@p) S2 else S3
|
  if (C) S1 else if (C2) S2 else if (C@p) S3
|
  if (C) S1 else if (C2) S2 else if (C@p) S3 else S4
)

@script:python depends on report@
p << e.p;
C << e.C;
@@
import re
# A test that changes what it tests, as a ++ or an assignment does, may
# find another answer the second time.
if not re.search(r"\+\+|--|[^=!<>]=[^=]", C):
    coccilib.report.print_report(p[0], "an else if that tests what an if before it tested")
