// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Functions the tree does without: rand() and its kin are no source of
// secrets (getrandom() is), strtok() and the time and user database
// functions keep hidden state (the _r forms do not), gets(), tmpnam(),
// tempnam() and mktemp() are unsafe by design, vfork(), alloca(),
// setjmp() and longjmp() defeat the compiler's checks, usleep() and
// signal() are obsolete (nanosleep() and sigaction() are not), and
// abort() and assert() belong to the tests, where they fail CI.

virtual report

@r@
attribute name SEC;
identifier f = {rand, srand, random, srandom, rand_r, drand48, lrand48,
		mrand48, strtok, gets, tmpnam, tempnam, mktemp, vfork, alloca,
		setjmp, longjmp, sigsetjmp, siglongjmp, usleep, signal,
		asctime, ctime, gmtime, localtime, getpwnam, getpwuid,
		getgrnam, getgrgid, getlogin, ttyname, bzero, bcopy, index,
		rindex, getwd, abort, assert};
position p;
@@
  f@p(...)

@script:python depends on report@
p << r.p;
f << r.f;
@@
# The tests may use what they exercise, and abort() and assert() fail
# CI there.
if not p[0].file.startswith("testing/"):
    coccilib.report.print_report(p[0], "%s() is not used in the tree" % f)
