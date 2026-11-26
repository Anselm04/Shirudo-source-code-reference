// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A descriptor names one file for good; a path is looked up again at
// every call that takes it. A function that holds a descriptor opened
// from a path, or passed in with it, and hands the same path to
// realpath() or readlink() learns where the name leads now, which a
// rename or a swapped link sends elsewhere than the descriptor: walk
// from the descriptor, or open each name once.

virtual report

@passed@
attribute name SEC;
identifier f, path;
identifier fd =~ "fd";
identifier lookup = {realpath, readlink};
type T;
position p;
@@
T f(..., int fd, ..., char *path, ...)
{
  <+...
  lookup@p(path, ...)
  ...+>
}

@passed_before@
identifier f, path;
identifier fd =~ "fd";
identifier lookup = {realpath, readlink};
type T;
position p;
@@
T f(..., char *path, ..., int fd, ...)
{
  <+...
  lookup@p(path, ...)
  ...+>
}

@opened exists@
expression fd, path, E, E1;
identifier open_fn = {open, openat, fopen};
identifier lookup = {realpath, readlink};
position p;
@@
(
  fd = open_fn(path, ...)
|
  fd = open_fn(E, path, ...)
)
  ... when != path = E1
  lookup@p(path, ...)

@script:python depends on report@
p << passed.p;
fd << passed.fd;
path << passed.path;
lookup << passed.lookup;
@@
coccilib.report.print_report(p[0], "%s() resolves %s by name again, where the descriptor %s is at hand" % (lookup, path, fd))

@script:python depends on report@
p << passed_before.p;
fd << passed_before.fd;
path << passed_before.path;
lookup << passed_before.lookup;
@@
coccilib.report.print_report(p[0], "%s() resolves %s by name again, where the descriptor %s is at hand" % (lookup, path, fd))

@script:python depends on report@
p << opened.p;
fd << opened.fd;
path << opened.path;
lookup << opened.lookup;
@@
coccilib.report.print_report(p[0], "%s() resolves %s by name again, where the descriptor %s is at hand" % (lookup, path, fd))
