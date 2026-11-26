// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// strerror() takes a positive error number. Given a return code that
// holds a negative one, as ret = -errno or the ret a test found below 0
// does, it prints "Unknown error -22" where the message was to say why:
// pass strerror(-ret).

virtual report

@r exists@
attribute name SEC;
identifier X;
expression E, E1;
position p;
@@
  X = -E;
  ... when != X = E1
  strerror@p(X)

@b@
identifier X;
position p;
@@
  if (X < 0) {
  <+... strerror@p(X) ...+>
  }

@script:python depends on report@
p << r.p;
X << r.X;
@@
coccilib.report.print_report(p[0], "strerror() of %s, which holds a negative error number" % X)

@script:python depends on report@
p << b.p;
X << b.X;
@@
coccilib.report.print_report(p[0], "strerror() of %s, which holds a negative error number" % X)
