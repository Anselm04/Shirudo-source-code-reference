// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A memcpy() of a string literal under a length that is neither the
// literal's nor the literal's with its terminator copies more or less
// than the literal. A compare is literal_count's, under any number.

virtual report

@r@
attribute name SEC;
expression E;
constant char[] S;
constant N;
identifier f = {memcpy};
position p;
@@
(
  f@p(E, S, N)
|
  f@p(S, E, N)
)

@script:python depends on report@
p << r.p;
S << r.S;
N << r.N;
f << r.f;
@@
import ast
try:
    text = ast.literal_eval(S)
    n = int(N, 0)
except Exception:
    text = None
if text is not None and n not in (len(text.encode()), len(text.encode()) + 1):
    coccilib.report.print_report(p[0], "%s() of %d bytes against a %d-byte literal" % (f, n, len(text.encode())))
