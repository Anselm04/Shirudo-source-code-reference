// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A local that a goto jumps over the assignment of, and that is read
// after the label, is read uninitialized on that path, which is
// undefined, and which a compiler reports or not with its version and
// optimizations: initialize it where it is declared.

virtual report

@r disable decl_init exists@
attribute name SEC;
type T;
identifier x, l;
expression E;
position p;
@@
  T x;
  ... when != x
  goto l;
  ...
l:
  ... when != x = E
      when != &x
(
  x = E
|
  &x
|
  sizeof(x)
|
  x@p
)

@script:python depends on report@
p << r.p;
x << r.x;
T << r.T;
@@
import re
# A for loop that assigns x in its header is no read before assignment.
line = open(p[0].file).read().split("\n")[int(p[0].line) - 1]
header = re.search(r"\bfor\s*\(\s*%s\s*=" % re.escape(x), line)
if not header and "[" not in T and not T.startswith(("struct", "union")):
    coccilib.report.print_report(p[0], "%s is read uninitialized when a goto jumps over its assignment" % x)
