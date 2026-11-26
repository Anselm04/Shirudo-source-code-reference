// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// No (void) casts: a __must_check result is checked, a result callers
// may ignore needs none, every build takes -Wno-unused-parameter, and an
// unused variable goes. The type check of min() and max() is the
// exception.

virtual patch
virtual report

@r depends on report@
attribute name SEC;
expression E;
position p;
@@
  (void)@p E

@script:python depends on report@
p << r.p;
@@
if p[0].current_element not in ("min", "max", "__minmax"):
    coccilib.report.print_report(p[0], "drop the (void) cast")

@depends on patch@
expression E;
identifier x;
@@
(
- (void)x;
|
- (void)
  E
)
