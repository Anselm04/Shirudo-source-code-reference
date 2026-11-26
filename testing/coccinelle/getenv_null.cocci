// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// getenv() returns NULL for a variable that is not set (CERT C EXP34-C),
// which the environment of a command run by hand, by systemd or by a
// test decides: its result is tested before it is read, in the same
// condition as in value && value[0], or before. cert_misc refuses it
// passed on unchecked; this rule follows it into a variable.

virtual report

@r exists@
attribute name SEC;
expression E, E1, N;
identifier g = {getenv, secure_getenv};
identifier f = {strlen, strnlen, strcmp, strncmp, strchr, strrchr, strstr,
		strpbrk, strspn, strcspn, xstrdup, xstrndup, strscpy,
		parse_u64, parse_s64, parse_x64, str_has_prefix,
		str_skip_prefix, memcpy, open, fopen, realpath, stat, lstat,
		access};
type T;
identifier x;
position p2;
@@
(
  E = g(N);
  ... when != E
      when != E = E1
(
  *E@p2
|
  E@p2[...]
|
  f(..., E@p2, ...)
)
|
  T x = g(N);
  ... when != x
      when != x = E1
(
  *x@p2
|
  x@p2[...]
|
  f(..., x@p2, ...)
)
)

@script:python depends on report@
p2 << r.p2;
@@
import re
# What comes before the read in its statement: a test there, as in
# value && value[0] or !value || f(value), guards it.
lines = open(p2[0].file).read().split("\n")
line, col = int(p2[0].line), int(p2[0].column)
before = "\n".join(lines[max(0, line - 6):line - 1] + [lines[line - 1][:col]])
before = re.split(r"[;{}]", before)[-1]
read = lines[line - 1][col:int(p2[0].column_end)]
name = r"\s*".join(re.escape(t) for t in re.findall(r"\w+|[^\w\s]+", read))
test = r"(!\s*%s\s*\|\||\b%s\s*(&&|\?)|\b%s\s*[!=]=\s*NULL)" % (name, name, name)
if not re.search(test, before):
    coccilib.report.print_report(p2[0], "%s is read before its NULL test; getenv() returns NULL for a variable that is not set" % read)
