// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A memset() of a local that nothing reads afterwards is a dead store
// the compiler drops; scrub with memzero_explicit().

virtual patch
virtual report

@r@
attribute name SEC;
identifier x;
expression C, L;
position p;
type T;
@@
(
  T x[C];
|
  T x;
)
  ... when any
(
  memset@p(x, 0, L);
|
  memset@p(&x, 0, L);
)
  ... when != x
      when != &x

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "a memset() nothing reads afterwards may be dropped; use memzero_explicit()")

@depends on patch@
identifier r.x;
expression L;
position r.p;
@@
(
- memset@p(x, 0, L);
+ memzero_explicit(x, L);
|
- memset@p(&x, 0, L);
+ memzero_explicit(&x, L);
)
