// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// An allocation sized for another type than the pointer it is stored
// in, and a free of memory no allocator returned: an address of a
// variable, or an array on the stack.

virtual report

@r@
attribute name SEC;
type T1, T2;
T1 *P;
position p;
identifier alloc = {xmalloc, xcalloc};
expression N;
@@
(
  P = xmalloc@p(sizeof(T2))
|
  P = xcalloc@p(N, sizeof(T2))
)

@script:python depends on report@
p << r.p;
T1 << r.T1;
T2 << r.T2;
@@
norm = lambda t: t.replace("const ", "").replace(" ", "")
if norm(T1) != norm(T2) and norm(T1) not in ("void", "char", "__u8"):
    coccilib.report.print_report(p[0], "allocated with sizeof(%s) for a %s *" % (T2, T1))

@nondyn@
type T;
identifier x;
expression C, S;
identifier fr = {xfree, xstrfree, libc_free};
position p;
@@
(
  T x[C];
  ...
  fr@p(x, ...);
|
  fr@p(&x, ...);
)

@script:python depends on report@
p << nondyn.p;
@@
coccilib.report.print_report(p[0], "a free of memory no allocator returned")
