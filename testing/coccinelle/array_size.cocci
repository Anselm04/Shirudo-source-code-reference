// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Count an array's elements with ARRAY_SIZE(), which refuses a pointer,
// and define it in <shirudo/misc.h> alone. A macro writes its argument
// in parentheses, (a)[0], which a pattern of a[0] alone does not match.

virtual patch
virtual report

@r@
attribute name SEC;
expression E;
position p;
@@
(
  sizeof(E)@p / sizeof(E[...])
|
  sizeof(E)@p / sizeof((E)[...])
|
  sizeof(E)@p / sizeof(*E)
|
  sizeof(E)@p / sizeof(*(E))
)

// The definition itself is spared, and another one is reported but not
// rewritten into one that names itself: it goes, by hand. Coccinelle
// names no macro a match is in, so the line tells.
@script:python@
p << r.p;
@@
with open(p[0].file) as f:
    line = f.readlines()[int(p[0].line) - 1]
if line.startswith("#define ARRAY_SIZE(") and \
   p[0].file.endswith("include/shirudo/misc.h"):
    cocci.include_match(False)

@script:python depends on patch@
p << r.p;
@@
with open(p[0].file) as f:
    line = f.readlines()[int(p[0].line) - 1]
if line.startswith("#define ARRAY_SIZE("):
    cocci.include_match(False)

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "use ARRAY_SIZE()")

@depends on patch@
expression r.E;
position r.p;
@@
(
- sizeof(E)@p / sizeof(E[...])
+ ARRAY_SIZE(E)
|
- sizeof(E)@p / sizeof((E)[...])
+ ARRAY_SIZE(E)
|
- sizeof(E)@p / sizeof(*E)
+ ARRAY_SIZE(E)
|
- sizeof(E)@p / sizeof(*(E))
+ ARRAY_SIZE(E)
)

// ARRAY_SIZE() checks for an array itself.
@depends on patch@
expression E;
@@
- ARRAY_SIZE(E) + __must_be_array(E)
+ ARRAY_SIZE(E)
