// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// errno describes the last call that failed and is unspecified after one
// that succeeded (CERT C ERR30-C): a cleanup call between a failure and
// the read of its errno may change it, and the error reported, or the
// one a test takes for harmless, is then another. Keep the errno, or the
// return value that carries it, before the cleanup. The pr_*() functions
// keep errno.

virtual report

@r exists@
attribute name SEC;
identifier g = {close, closedir, fclose, unlink, unlinkat, rmdir, munmap,
		umount, umount2, rename, renameat, fsync, fflush, flock,
		ftruncate, fchmod, chmod, write, syslog, fprintf, printf,
		fputs, puts};
identifier f;
expression E, E1, X;
position p1, p;
@@
  g@p1(...);
  ... when != f(...)
      when != errno = E
(
  return X@p;
|
  E1 = X@p;
)

@script:python depends on report@
p1 << r.p1;
p << r.p;
g << r.g;
X << r.X;
@@
import re
m = re.search(r'\berrno\b', X)
# A call before errno in the same expression set it: unlink(p) ? -errno : 0.
if m and not re.search(r'\b[A-Za-z_]\w*\s*\(', X[:m.start()]):
    coccilib.report.print_report(p[0], "errno read after %s() at line %s, which may have changed it" % (g, p1[0].line))
