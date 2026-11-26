// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A member a designated initializer sets twice keeps only the second
// value; the first was meant for another member.

virtual report

@r@
attribute name SEC;
identifier f, x;
type T;
expression E1, E2;
position p2;
@@
  T x = {..., .f = E1, ..., .f = E2@p2, ...};

@script:python depends on report@
p2 << r.p2;
f << r.f;
@@
coccilib.report.print_report(p2[0], "member %s is initialized twice" % f)
