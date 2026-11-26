// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// read(), pread(), recv(), readlink() and the getxattr() family fill a
// buffer and return a count; they write no terminator. A function that
// reads up to one, strlen(), strcmp(), strchr() and their kin, then
// runs past what was read, into what the buffer held before or beyond
// it. Between the read and such a use the buffer is terminated, with
// buf[n] = '\0' or span_to_str(), which also refuses a NUL among the
// bytes read. An array zeroed where it is declared and read into for
// one byte less than its size is terminated as it is.

virtual report

@zeroed3@
attribute name SEC;
identifier buf;
identifier rd3 = {read, pread, recv, readlink};
expression E;
type T;
position p;
@@
T buf[...] = {};
...
rd3@p(E, buf, sizeof(buf) - 1, ...)

@zeroed4@
identifier buf;
identifier rd4 = {readlinkat, getxattr, lgetxattr, fgetxattr};
expression E, E1;
type T;
position p;
@@
T buf[...] = {};
...
rd4@p(E, E1, buf, sizeof(buf) - 1, ...)

@r exists@
expression buf, E, E1;
identifier rd3 = {read, pread, recv, readlink};
identifier rd4 = {readlinkat, getxattr, lgetxattr, fgetxattr};
identifier strfn = {strlen, strcmp, strcasecmp, strchr, strrchr, strstr,
		    strcspn, strspn, strpbrk, strtok_r, strdup, xstrdup,
		    atoi, puts, hex_decode, sha256_digest_decode,
		    str_contains, str_equals_nocase, str_after_prefix,
		    str_after_prefix_nocase, str_has_prefix,
		    str_has_prefix_nocase};
identifier second = {strscpy, strcmp, strcasecmp, strstr, str_contains,
		     str_equals_nocase, str_after_prefix,
		     str_after_prefix_nocase};
position p1 != {zeroed3.p, zeroed4.p};
position p2;
@@
(
  rd3@p1(E, buf, ...)
|
  rd4@p1(E, E1, buf, ...)
)
... when != buf[...] = \('\0'\|0\)
    when != span_to_str(buf, ...)
(
  strfn@p2(buf, ...)
|
  second@p2(E, buf, ...)
)

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
@@
coccilib.report.print_report(p2[0], "takes for a string what line %s read, which nothing terminated" % p1[0].line)
