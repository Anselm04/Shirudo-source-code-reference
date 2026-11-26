// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// CERT C: a char array sized as long as the string literal it holds
// has no room for the terminating NUL (STR36-C), a char cannot tell
// EOF from a byte getc() returned (FIO34-C), and getenv() returns NULL
// for an unset variable (EXP34-C).

virtual report

@strbound@
attribute name SEC;
identifier x;
constant C;
constant char[] S;
position p;
@@
  char x@p[C] = S;

@script:python depends on report@
p << strbound.p;
C << strbound.C;
S << strbound.S;
@@
import ast
try:
    n, text = int(C, 0), ast.literal_eval(S)
except Exception:
    n = None
if n is not None and n <= len(text.encode()):
    coccilib.report.print_report(p[0], "no room for the NUL of the string literal; use []")

@getc@
char c;
identifier f = {getc, fgetc, getchar, getc_unlocked, fgetc_unlocked};
position p;
@@
  c =@p f(...)

@script:python depends on report@
p << getc.p;
f << getc.f;
@@
coccilib.report.print_report(p[0], "keep what %s() returns in an int" % f)

@getenv@
identifier f = {strlen, strcmp, strncmp, strchr, strrchr, strstr, strdup,
		xstrdup, strscpy, strtol, parse_u64, atoi};
expression E;
position p;
@@
  f@p(..., getenv(E), ...)

@script:python depends on report@
p << getenv.p;
@@
coccilib.report.print_report(p[0], "getenv() may return NULL")
