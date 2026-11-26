// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Memory is neither read nor freed again once it has been freed.

virtual report

@r exists@
attribute name SEC;
expression E, E1;
identifier fr = {xfree, xstrfree, libc_free, X509_free, EVP_PKEY_free,
		 BIO_free, BN_free, CMS_ContentInfo_free, btf__free,
		 curl_slist_free_all, curl_free};
identifier fld;
position p1, p2;
@@
  fr@p1(E, ...);
  ... when != E = E1
      when != &E
(
  E->fld@p2
|
  *E@p2
|
  E[...]@p2
|
  fr@p2(E, ...)
|
  memcpy@p2(..., E, ...)
)

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
E << r.E;
@@
# An element freed in a loop is another one on the next turn.
if "[" not in E:
    coccilib.report.print_report(p2[0], "%s is used after it was freed at line %s" % (E, p1[0].line))
