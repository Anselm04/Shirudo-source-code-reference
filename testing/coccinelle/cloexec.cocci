// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Open every descriptor close-on-exec, so that none reaches a program
// the operator helper runs.

virtual report

@initialize:python@
@@
closing = set()

@ok@
attribute name SEC;
expression A, B, C, D;
position p;
@@
(
  open@p(A, <+... O_CLOEXEC ...+>, ...)
|
  openat@p(A, B, <+... O_CLOEXEC ...+>, ...)
|
  socket@p(A, <+... SOCK_CLOEXEC ...+>, ...)
|
  memfd_create@p(A, <+... MFD_CLOEXEC ...+>)
|
  pipe2@p(A, <+... O_CLOEXEC ...+>)
|
  accept4@p(A, B, C, <+... SOCK_CLOEXEC ...+>)
|
  dup3@p(A, B, <+... O_CLOEXEC ...+>)
)

@script:python@
p << ok.p;
@@
closing.add((p[0].file, p[0].line, p[0].column))

@r@
identifier f = {open, openat, socket, memfd_create, pipe2, accept4, dup3,
		pipe, accept, dup, dup2, creat, epoll_create, inotify_init,
		signalfd, eventfd, timerfd_create};
position p;
@@
  f@p(...)

@script:python depends on report@
p << r.p;
f << r.f;
@@
# harden_stdio() points a closed standard descriptor at /dev/null for
# good, a program it runs included.
if (p[0].file, p[0].line, p[0].column) not in closing and \
   p[0].current_element != "harden_stdio" and \
   not p[0].file.startswith(("bpf/", "upatches/", "testing/")):
    coccilib.report.print_report(p[0], "%s() without close-on-exec" % f)

@mode@
expression P;
constant char[] M;
position q;
@@
(
  fopen@q(P, M)
|
  freopen@q(P, M, ...)
)

@script:python depends on report@
q << mode.q;
M << mode.M;
@@
if "e" not in M.strip('"') and not q[0].file.startswith("testing/"):
    coccilib.report.print_report(q[0], "open the stream close-on-exec with \"e\" in its mode")
