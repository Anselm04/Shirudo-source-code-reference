// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The allocators return NULL on failure; use what they return only
// after testing it.

virtual report

@r exists@
attribute name SEC;
expression E, E1;
identifier fld;
identifier alloc = {xmalloc, xcalloc, xreallocarray, xstrdup, xstrndup,
		    xasprintf};
identifier f = {strlen, strcmp, strncmp, strchr, strrchr, strstr, memcpy,
		memmove, memcmp, memset, strscpy, strsprintf};
position p1, p2;
@@
  E = alloc@p1(...);
  ... when != E == NULL
      when != E != NULL
      when != !E
      when != E = E1
(
  E->fld@p2
|
  *E@p2
|
  E[...]@p2
|
  f@p2(..., E, ...)
)

@script:python depends on report@
p2 << r.p2;
E << r.E;
@@
coccilib.report.print_report(p2[0], "%s is used before the allocation is checked" % E)
