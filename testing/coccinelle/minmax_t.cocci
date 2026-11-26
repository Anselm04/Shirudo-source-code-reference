// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// min_t() and max_t() convert both values, which can cut one short; use
// min() and max() wherever they take the two as they are, which they do
// for values of one type and for a non-negative constant.

virtual report

@r@
attribute name SEC;
type T;
T A, B;
constant C;
position p;
identifier f = {min_t, max_t};
@@
(
  f@p(T, A, B)
|
  f@p(T, A, C)
|
  f@p(T, C, A)
)

@script:python depends on report@
p << r.p;
f << r.f;
@@
coccilib.report.print_report(p[0], "%s() converts what %s() takes as it is" % (f, f[:3]))
