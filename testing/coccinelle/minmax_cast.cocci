// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A cast inside min() or max() is min_t() spelled by hand: give the
// value its right type, or use min_t() where it cannot have one.

virtual report

@r disable drop_cast@
attribute name SEC;
type T;
expression A, B;
identifier f = {min, max};
position p;
@@
(
  f@p((T)A, B)
|
  f@p(A, (T)B)
)

@script:python depends on report@
p << r.p;
f << r.f;
@@
line = open(p[0].file).read().split("\n")[int(p[0].line) - 1]
if not line.startswith("#define"):
    coccilib.report.print_report(p[0], "a cast inside %s()" % f)
