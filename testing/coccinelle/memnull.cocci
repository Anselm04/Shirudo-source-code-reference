// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The mem*() and str*() functions take no NULL pointer, not even with a
// length of 0, and memcpy() takes no overlap: an empty buffer is copied
// under a test of its length, and an overlapping one with memmove().

virtual report

@r@
attribute name SEC;
identifier f = {memcpy, memmove, memset, memcmp, memchr, strlen, strnlen,
		strcmp, strncmp, strchr, strrchr, strstr, strscpy,
		memzero_explicit, memneq_explicit};
expression list es;
expression E, F, L;
position p;
@@
(
  f@p(..., NULL, ...)
|
  memcpy@p(E, E + F, L)
|
  memcpy@p(E + F, E, L)
)

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "NULL or an overlapping buffer passed to a memory or string function")
