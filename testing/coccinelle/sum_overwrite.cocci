// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A total built up step by step, each step adding what its case needs,
// loses what came before when one step stores a sum of its own where it
// meant to add it: the size of the status JSON dropped the room for the
// loaded upatches once the eventlog was asked for, and status printed
// nothing on a target with many.

virtual report

@r exists@
attribute name SEC;
identifier x;
expression A, B1, B2, C, E, E1;
position p;
@@
(
  x = A;
|
  x += A;
)
  ... when != x
  if (C) x =@p B1 + B2;
  ... when != x = E1
  x += E;

@script:python depends on report@
p << r.p;
x << r.x;
A << r.A;
B1 << r.B1;
B2 << r.B2;
@@
import re
if A not in ("0", "0U", "0u", "NULL") and \
   not re.search(r"\b%s\b" % re.escape(x), B1 + " " + B2):
    coccilib.report.print_report(p[0], "%s is stored over between the additions to it; += may be meant" % x)
