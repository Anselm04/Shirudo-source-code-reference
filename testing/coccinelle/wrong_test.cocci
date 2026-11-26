// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The test right after an assignment checks what was assigned: in
// x = f(); if (y < 0) or if (y == NULL), the failure of f() goes through
// untested. A y that f() fills in through an argument is meant.

virtual report

@r disable is_null, isnt_null1@
attribute name SEC;
identifier x, y, f;
expression list es;
position p;
statement S;
@@
  x = f(es);
  if (\(y@p == NULL\|y@p < 0\)) S

@script:python depends on report@
p << r.p;
x << r.x;
y << r.y;
es << r.es;
@@
import re
if x != y and not re.search(r'\b%s\b' % re.escape(y), str(es)):
    coccilib.report.print_report(p[0], "%s is assigned and %s tested" % (x, y))
