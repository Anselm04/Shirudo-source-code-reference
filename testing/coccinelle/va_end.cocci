// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Every va_start() and va_copy() is matched by a va_end() on each path
// out of the function.

virtual report

@r exists@
attribute name SEC;
expression A, B;
position p;
@@
(
  va_start@p(A, ...);
|
  va_copy@p(A, B);
)
  ... when != va_end(A);
  return ...;

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "no va_end() on a path from here")
