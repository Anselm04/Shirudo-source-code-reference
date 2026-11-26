// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The <ctype.h> functions take an unsigned char's value or EOF; a char
// above 0x7f is negative where char is signed, which is undefined.

virtual patch
virtual report

@r@
attribute name SEC;
identifier f = {isalnum, isalpha, isascii, isblank, iscntrl, isdigit,
		isgraph, islower, isprint, ispunct, isspace, isupper,
		isxdigit, tolower, toupper};
char C;
position p;
@@
  f@p(C)

@script:python depends on report@
p << r.p;
f << r.f;
@@
coccilib.report.print_report(p[0], "cast the argument of %s() to __u8" % f)

@depends on patch@
identifier r.f;
char r.C;
position r.p;
@@
  f@p(
+ (__u8)
  C)
