// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A descriptor is not used again once it has been closed: its number may
// already name another file the process opened since, which a second
// close(), a read or a write then hits (CERT C FIO46-C).

virtual report

@r exists@
attribute name SEC;
expression fd, E;
identifier f;
position p1, p2;
@@
  close@p1(fd);
  ... when != fd = E
      when != &fd
      when != _exit(...)
      when != exit(...)
      when != abort()
  f@p2(..., fd, ...)

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
fd << r.fd;
f << r.f;
@@
# An element closed in a loop is another one on the next turn.
if "[" not in fd:
    coccilib.report.print_report(p2[0], "%s() of %s, closed at line %s" % (f, fd, p1[0].line))
