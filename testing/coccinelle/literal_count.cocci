// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A comparison with a string literal takes its length from the literal,
// sizeof(lit), sizeof(lit) - 1 or a helper of <shirudo/string.h> that
// does, not from a number beside it: a count one short compares less
// than the literal and still passes, one too long reads past it, and
// neither shows until the literal changes.

virtual report

@initialize:python@
@@
# A name, a sizeof or a strlen() is no number.
def counted(p, f, n):
    try:
        int(n, 0)
    except ValueError:
        return
    coccilib.report.print_report(p[0], "%s() of a literal with the length %s written out" % (f, n))

@cmp@
attribute name SEC;
expression E;
constant char[] S;
constant N;
identifier f = {memcmp, bcmp, strncmp, strncasecmp};
position p;
@@
(
  f@p(E, S, N)
|
  f@p(S, E, N)
)

@script:python depends on report@
p << cmp.p;
N << cmp.N;
f << cmp.f;
@@
counted(p, f, N)

@chr@
expression E;
constant char[] S;
constant N;
identifier f = {memchr, memrchr};
position p;
@@
  f@p(S, E, N)

@script:python depends on report@
p << chr.p;
N << chr.N;
f << chr.f;
@@
counted(p, f, N)

@mem@
expression E, L;
constant char[] S;
constant N;
position p;
@@
  memmem@p(E, L, S, N)

@script:python depends on report@
p << mem.p;
N << mem.N;
@@
counted(p, "memmem", N)
