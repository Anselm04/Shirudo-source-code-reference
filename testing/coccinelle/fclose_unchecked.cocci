// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// fclose() of a stream written to writes what stdio still buffers and
// reports a failure to; with its result ignored, a file that was not
// written passes for one that was (CERT C ERR33-C).

virtual report

@r exists@
attribute name SEC;
expression F, A, M;
identifier o = {fopen, fdopen};
identifier f;
type T;
position p;
@@
(
  F = o(A, M);
  ...
  fclose@p(F);
|
  T f = o(A, M);
  ...
  fclose@p(f);
)

@script:python depends on report@
p << r.p;
M << r.M;
@@
if any(c in M for c in "wa+"):
    coccilib.report.print_report(p[0], "fclose() of a stream opened %s for writing, its result ignored" % M)
