// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The key derivations of util/tpm_wire.c that attest challenge protects a
 * credential with, with SHA-256, HMAC and AES modelled as any result: for
 * every label of up to LABEL_MAX bytes and every length, KDFa, KDFe and
 * credential protection hash only whole inputs and refuse longer ones.
 */

#include "proof.h"
#include "../../../util/tpm_wire.c"

static int any_result(void)
{
	int ret;

	return ret;
}

int sha256_init(struct sha256_ctx *ctx)
{
	return any_result();
}

int sha256_update(struct sha256_ctx *ctx, const void *data, size_t len)
{
	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	return any_result();
}

int sha256_final(struct sha256_ctx *ctx, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	return any_result();
}

void sha256_free(struct sha256_ctx *ctx)
{
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	return any_result();
}

int hmac_sha256(const __u8 *key, size_t key_len, const void *data,
		size_t len, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_r_ok(key, key_len) &&
			 __CPROVER_r_ok(data, len), "MACs only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a MAC's room");
	__CPROVER_havoc_slice(out, 32);
	return any_result();
}

int aes128_cfb_encrypt(const __u8 key[16], const __u8 *in, size_t len,
		       __u8 *out)
{
	__CPROVER_assert(__CPROVER_r_ok(key, 16) && __CPROVER_r_ok(in, len) &&
			 __CPROVER_w_ok(out, len), "encrypts only its input");
	__CPROVER_havoc_slice(out, len);
	return any_result();
}

static __u8 *digest(void)
{
	return any_bytes(32);
}

static char *label(void)
{
	char *s = any_bytes(LABEL_MAX + 1);

	s[LABEL_MAX] = '\0';
	return s;
}

void harness(void)
{
	size_t key_len, u_len, v_len, out_len;
	__u8 *out;

	__CPROVER_assume(key_len <= 64 && out_len <= OUT_MAX);
	out = any_bytes(OUT_MAX);
	if (!tpm_kdfa(any_bytes(64), key_len, label(),
		      any_bytes(TPM_NAME_LEN), u_len,
		      any_bytes(TPM_NAME_LEN), v_len, out, out_len))
		__CPROVER_assert(u_len <= TPM_NAME_LEN && v_len <= TPM_NAME_LEN,
				 "KDFa contexts of names");
	if (!tpm_kdfe(digest(), label(), any_bytes(64), u_len,
		      any_bytes(64), v_len, digest()))
		__CPROVER_assert(u_len <= 64 && v_len <= 64,
				 "KDFe parties of points");
	if (tpm_credential_protect(digest(), any_bytes(TPM_NAME_LEN), digest(),
				   any_bytes(TPM_ID_OBJECT_LEN)))
		return;
}
