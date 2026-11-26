// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// An error stored before a break is the loop's failure, and the code
// after the loop tests it before it acts. When a call that is not a
// cleanup runs after it untested and a store replaces it, the work after
// the loop went ahead on a failure nobody read: an upgrade unloaded part
// of the old version and loaded the new one after the listing of the old
// one had failed.

virtual report

@r exists@
attribute name SEC;
identifier ret;
identifier f != {close, closedir, fclose, gzclose, munmap, unlink, xfree,
		 xstrfree, libc_free, memzero_explicit, pr_err, pr_warn,
		 pr_info, pr_audit};
expression E, E1, E2;
position p1, p3;
@@
  ret@p1 = -E;
  ... when != ret
(
  ret@p3 = f(...);
|
  f(...);
  ... when != ret
  ret@p3 = E1;
|
  E2 = f(...);
  ... when != ret
  ret@p3 = E1;
)

@script:python depends on report@
p1 << r.p1;
p3 << r.p3;
ret << r.ret;
f << r.f;
@@
# A break in the pattern would end its path there, so the break comes
# from the line after the store.
lines = open(p1[0].file).read().split("\n")
after = lines[int(p1[0].line)].strip() if int(p1[0].line) < len(lines) else ""
if after == "break;":
    coccilib.report.print_report(p1[0], "%s is not tested after the loop before %s() runs, and line %s stores over it" % (ret, f, p3[0].line))
