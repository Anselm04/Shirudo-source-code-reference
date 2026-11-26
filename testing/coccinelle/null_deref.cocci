// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A pointer dereferenced in the branch of the test that found it NULL,
// before anything gave it another value: usually the error message or
// the cleanup of the failure that the test was there to catch. An
// operand of sizeof is not evaluated and does not count.

virtual report

@unevaluated@
attribute name SEC;
expression E;
identifier fld;
position p;
@@
sizeof(<+... \(E@p->fld\|*E@p\) ...+>)

@r exists@
expression E, E1;
identifier fld;
position p != unevaluated.p;
@@
if (\(E == NULL\|!E\)) {
  ... when != E = E1
      when != &E
(
  E@p->fld
|
  *E@p
)
  ... when any
}

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "dereferenced in the branch that found it NULL")
