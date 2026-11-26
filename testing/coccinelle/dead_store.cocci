// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A value stored in a local and stored over on every path, the error
// exits included, before anything reads it is lost: the error a call
// returned, say, which the second store was meant to keep, or a store
// that is dead code (CERT C MSC12-C). The compiler warns only of a local
// never read at all. Following every path of a long function can take
// minutes, so spatch gives up on a file after one, and check-coccinelle.sh
// names each file it gave up on.
#spatch --no-includes --timeout 60

virtual report

@r@
attribute name SEC;
local idexpression x;
expression E1, E2;
position p1, p2;
@@
  x@p1 = E1;
  ... when != x
      when != &x
      when strict
  x@p2 = E2;

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
x << r.x;
E2 << r.E2;
@@
import re
# A store that reads the value it replaces, x = x + 1, reads it first.
if not re.search(r"\b%s\b" % re.escape(x), E2):
    coccilib.report.print_report(p1[0],
        "%s stored here is stored over at line %s before any read" %
        (x, p2[0].line))
