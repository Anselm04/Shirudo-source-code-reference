// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// These OpenSSL functions return 1 on success, and 0 or a negative
// value on failure: a test of their truth takes an error for success.
// Compare with 1, or with 0 by <= or >.

virtual report

@initialize:python@
@@
compared = set()

@ok@
attribute name SEC;
identifier f = {EVP_PKEY_verify, EVP_PKEY_verify_init, EVP_PKEY_verify_recover,
		EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_derive,
		EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
		EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_decrypt,
		EVP_PKEY_decrypt_init, EVP_PKEY_encapsulate,
		EVP_PKEY_encapsulate_init, EVP_PKEY_decapsulate,
		EVP_PKEY_decapsulate_init, EVP_PKEY_keygen, EVP_PKEY_keygen_init,
		EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
		EVP_PKEY_CTX_set_signature_md, EVP_PKEY_CTX_set_rsa_padding,
		EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_mgf1_md,
		EVP_PKEY_CTX_set0_rsa_oaep_label, EVP_PKEY_CTX_set_params,
		EVP_DigestVerify, EVP_DigestVerifyInit, EVP_DigestVerifyUpdate,
		EVP_DigestVerifyFinal, EVP_DigestSign, EVP_DigestSignInit,
		EVP_DigestSignUpdate, EVP_DigestSignFinal, X509_verify,
		X509_REQ_verify, X509_CRL_verify, X509_verify_cert, RAND_bytes,
		RAND_priv_bytes, CMS_verify, PKCS7_verify, EVP_PKEY_check,
		EVP_PKEY_public_check};
position p;
@@
(
  f@p(...) == 1
|
  f@p(...) != 1
|
  f@p(...) <= 0
|
  f@p(...) > 0
)

@script:python@
p << ok.p;
@@
compared.add((p[0].file, p[0].line, p[0].column))

@r@
identifier f = {EVP_PKEY_verify, EVP_PKEY_verify_init, EVP_PKEY_verify_recover,
		EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_derive,
		EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
		EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_decrypt,
		EVP_PKEY_decrypt_init, EVP_PKEY_encapsulate,
		EVP_PKEY_encapsulate_init, EVP_PKEY_decapsulate,
		EVP_PKEY_decapsulate_init, EVP_PKEY_keygen, EVP_PKEY_keygen_init,
		EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
		EVP_PKEY_CTX_set_signature_md, EVP_PKEY_CTX_set_rsa_padding,
		EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_mgf1_md,
		EVP_PKEY_CTX_set0_rsa_oaep_label, EVP_PKEY_CTX_set_params,
		EVP_DigestVerify, EVP_DigestVerifyInit, EVP_DigestVerifyUpdate,
		EVP_DigestVerifyFinal, EVP_DigestSign, EVP_DigestSignInit,
		EVP_DigestSignUpdate, EVP_DigestSignFinal, X509_verify,
		X509_REQ_verify, X509_CRL_verify, X509_verify_cert, RAND_bytes,
		RAND_priv_bytes, CMS_verify, PKCS7_verify, EVP_PKEY_check,
		EVP_PKEY_public_check};
position p;
@@
  f@p(...)

@script:python depends on report@
p << r.p;
f << r.f;
@@
if (p[0].file, p[0].line, p[0].column) not in compared:
    coccilib.report.print_report(p[0], "compare the result of %s() with 1, or by <= 0" % f)
