// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// These free functions take NULL; a test before them only hides the call.

virtual patch
virtual report

@r depends on report@
attribute name SEC;
expression E, S;
position p;
@@
  if@p (E)
(
  xfree(E, S);
|
  xstrfree(E);
|
  libc_free(E);
|
  X509_free(E);
|
  X509_STORE_free(E);
|
  EVP_PKEY_free(E);
|
  EVP_PKEY_CTX_free(E);
|
  EVP_MD_CTX_free(E);
|
  BIO_free(E);
|
  BN_free(E);
|
  OSSL_PARAM_free(E);
|
  CMS_ContentInfo_free(E);
|
  btf__free(E);
|
  bpf_object__close(E);
|
  bpf_link__destroy(E);
|
  curl_slist_free_all(E);
|
  curl_free(E);
|
  curl_easy_cleanup(E);
|
  curl_url_cleanup(E);
)

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "the free function takes NULL; drop the test")

@depends on patch@
expression E, S;
@@
- if (E)
(
  xfree(E, S);
|
  xstrfree(E);
|
  libc_free(E);
|
  X509_free(E);
|
  X509_STORE_free(E);
|
  EVP_PKEY_free(E);
|
  EVP_PKEY_CTX_free(E);
|
  EVP_MD_CTX_free(E);
|
  BIO_free(E);
|
  BN_free(E);
|
  OSSL_PARAM_free(E);
|
  CMS_ContentInfo_free(E);
|
  btf__free(E);
|
  bpf_object__close(E);
|
  bpf_link__destroy(E);
|
  curl_slist_free_all(E);
|
  curl_free(E);
|
  curl_easy_cleanup(E);
|
  curl_url_cleanup(E);
)
