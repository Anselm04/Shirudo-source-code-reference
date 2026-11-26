// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Take the smaller or larger of two values with min() or max(), which
// evaluate each once and refuse operands of different types; min_t()
// and max_t() name the type when they differ.

virtual patch
virtual report

@r depends on report@
attribute name SEC;
expression A, B;
position p;
@@
(
  A <@p B ? A : B
|
  A <=@p B ? A : B
|
  A >@p B ? B : A
|
  A >=@p B ? B : A
|
  A >@p B ? A : B
|
  A >=@p B ? A : B
|
  A <@p B ? B : A
|
  A <=@p B ? B : A
)

@script:python depends on report@
p << r.p;
@@
if p[0].current_element not in ("min", "max", "__minmax"):
    coccilib.report.print_report(p[0], "use min() or max()")

@depends on patch@
expression A, B;
@@
(
- A < B ? A : B
+ min(A, B)
|
- A <= B ? A : B
+ min(A, B)
|
- A > B ? B : A
+ min(A, B)
|
- A >= B ? B : A
+ min(A, B)
|
- A > B ? A : B
+ max(A, B)
|
- A >= B ? A : B
+ max(A, B)
|
- A < B ? B : A
+ max(A, B)
|
- A <= B ? B : A
+ max(A, B)
)
