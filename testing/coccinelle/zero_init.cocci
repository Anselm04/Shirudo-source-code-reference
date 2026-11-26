// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Zero-initialize with = {}, the kernel's form, not = {0}.

virtual patch
virtual report

@r depends on report@
attribute name SEC;
type T;
identifier x;
position p;
@@
  T x@p = {0};

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "zero-initialize with = {}")

@depends on patch@
type T;
identifier x;
@@
  T x =
- {0}
+ {}
  ;
