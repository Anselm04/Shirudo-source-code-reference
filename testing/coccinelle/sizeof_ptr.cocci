// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// sizeof a pointer where the object it points to was meant: what is
// copied, cleared, compared, scrubbed, allocated or counted is the 8
// bytes of the pointer. The pointer is the object only where its own
// address goes to the same call, as in memcpy(&p, src, sizeof(p)). The
// type of a struct member comes from the header that declares it, so
// this rule reads the headers a file includes.

#spatch --include-headers-for-types --all-includes -I include -I util -I .

virtual report

@own@
attribute name SEC;
type T;
T *P;
identifier f;
position p;
@@
(
  f(..., &P, ..., sizeof@p(P), ...)
|
  f(..., sizeof@p(P), ..., &P, ...)
)

@r@
type T;
T *P;
expression E, I;
position p != own.p;
@@
(
  sizeof(*E)
|
  sizeof(E[I])
|
  sizeof@p(P)
|
  sizeof@p(sizeof(...))
)

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "sizeof of a pointer; the object it points to may be meant")
