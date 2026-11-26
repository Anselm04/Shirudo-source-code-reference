// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Pointer arithmetic counts elements, not bytes: a sizeof added to a
// pointer to anything wider than a byte moves it that many elements
// (CERT C ARR39-C). Step through a byte pointer, or count elements.

virtual report

@r@
attribute name SEC;
type T, T2;
T *ptr;
expression E;
position p;
@@
(
  ptr + sizeof(E)@p
|
  ptr + sizeof(T2)@p
|
  ptr - sizeof(E)@p
|
  ptr - sizeof(T2)@p
|
  ptr += sizeof(E)@p
|
  ptr += sizeof(T2)@p
|
  ptr -= sizeof(E)@p
|
  ptr -= sizeof(T2)@p
)

@script:python depends on report@
p << r.p;
T << r.T;
@@
if T.replace("const ", "").strip() not in ("char", "unsigned char", "signed char", "__u8", "__s8", "void"):
    coccilib.report.print_report(p[0], "a byte count added to a %s pointer" % T)
