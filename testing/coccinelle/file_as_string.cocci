// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// read_file(), read_fd() and the readers of a package member hand over
// the bytes of a file with their length, and a terminator behind them
// that says nothing of the bytes: a file can hold a NUL. A function
// that reads up to a terminator, strstr(), strtok_r(), strlen() and
// their kin, takes such a file to end at its first NUL, so that what it
// searches or walks is not what was read, hashed or signed, and what
// stands behind the NUL is never looked at. Before such a use the
// bytes go, with their length, to what checks them: span_to_str(), a
// parser that takes a length, or the reader's own check.

virtual report

@r exists@
attribute name SEC;
expression buf, len, E, E1, E2, E3, E4, E5;
identifier strfn = {strlen, strcmp, strcasecmp, strchr, strrchr, strstr,
		    strcspn, strspn, strpbrk, strtok_r, strdup, xstrdup,
		    atoi, puts, hex_decode, sha256_digest_decode,
		    str_contains, str_equals_nocase, str_after_prefix,
		    str_after_prefix_nocase, str_has_prefix,
		    str_has_prefix_nocase};
identifier second = {strscpy, strcmp, strcasecmp, strstr, str_contains,
		     str_equals_nocase, str_after_prefix,
		     str_after_prefix_nocase};
identifier f;
position p1, p2;
@@
(
  read_file@p1(E, E1, &buf, &len)
|
  read_fd@p1(E, E1, E2, &buf, &len)
|
  bpm_pkg_read_member@p1(E, E1, &buf, &len, E2)
|
  \(bpm_pkg_read_member_in@p1\|bpm_pkg_read_member_fd@p1\)(E, E1, E2, E3, E4, &buf, &len, E5)
)
... when != f(..., buf, len, ...)
    when != f(..., (char *)buf, len, ...)
(
  strfn@p2(buf, ...)
|
  strfn@p2((char *)buf, ...)
|
  second@p2(E, buf, ...)
)

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
@@
coccilib.report.print_report(p2[0], "takes for a string the bytes line %s read, before anything saw them with their length" % p1[0].line)
