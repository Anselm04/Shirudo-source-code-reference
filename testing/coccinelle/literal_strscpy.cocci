// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A string literal copied into an array with strscpy() leaves a result
// to check that cannot fail until the literal outgrows the array, and
// then fails at run time on a path nobody tests: strscpy_literal()
// refuses that literal when it is built.

virtual report

@r@
attribute name SEC;
expression E;
constant char[] S;
position p;
@@
  strscpy@p(E, S, sizeof(E))

// The unit cases of strscpy() itself copy literals to test it.
@script:python depends on report@
p << r.p;
@@
if not p[0].file.endswith("testing/unit/string.c"):
    coccilib.report.print_report(p[0], "a literal copied into an array with strscpy(), not strscpy_literal()")
