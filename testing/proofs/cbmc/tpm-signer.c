// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tpm_attest_signer() and tpm_attest_verify() of util/tpm_wire.c, with
 * which attest verify decides that a quote or certification is the
 * pinned attestation key's: the signer is that key exactly when it is the
 * key's name qualified under the endorsement hierarchy, and a signature
 * passes only over the SHA-256 of exactly the attestation's bytes.
 */

#include "proof.h"
#include "../../../util/tpm_wire.c"

/* What the last hash was given and gave. */
static __u8 hashed[4 + TPM_NAME_LEN], digest[32];
static const void *hashed_data;
static size_t hashed_len;
static bool verified;

static int any_result(void)
{
	int ret;

	return ret;
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	if (len <= sizeof(hashed))
		memcpy(hashed, data, len);
	hashed_data = data;
	hashed_len = len;
	__CPROVER_havoc_slice(out, 32);
	memcpy(digest, out, 32);
	return any_result();
}

int ecdsa_p256_verify(const __u8 x[32], const __u8 y[32], const __u8 d[32],
		      const __u8 r[32], const __u8 s[32])
{
	__CPROVER_assert(!memcmp(d, digest, 32), "the digest it was given");
	verified = true;
	return any_result();
}

static void signer(void)
{
	__u8 *ak_name = any_bytes(TPM_NAME_LEN);
	struct tpm_attest a;
	bool is = false, qualified;
	size_t i;

	__CPROVER_assume(a.signer_len <= TPM_NAME_LEN);
	if (tpm_attest_signer(&a, ak_name, &is))
		return;
	__CPROVER_assert(hashed_len == sizeof(hashed) &&
			 get_be32(hashed) == TPM_RH_ENDORSEMENT,
			 "the endorsement hierarchy's handle");
	for (i = 0; i < TPM_NAME_LEN; i++)
		__CPROVER_assert(hashed[4 + i] == ak_name[i],
				 "then the key's name");
	qualified = a.signer_len == TPM_NAME_LEN &&
		    get_be16(a.signer) == TPM_ALG_SHA256;
	for (i = 0; i < 32; i++)
		qualified = qualified && a.signer[2 + i] == digest[i];
	__CPROVER_assert(is == qualified,
			 "the signer is the key's qualified name");
}

static void signature(void)
{
	size_t attest_len, sig_len;
	__u8 *attest, *sig;
	int ret;

	__CPROVER_assume(attest_len <= 16 && sig_len <= 72);
	attest = any_bytes(attest_len);
	sig = any_bytes(sig_len);
	verified = false;
	ret = tpm_attest_verify(attest, attest_len, sig, sig_len,
				any_bytes(32), any_bytes(32));
	if (tpm_ecdsa_signature_parse(sig, sig_len, any_bytes(32),
				      any_bytes(32))) {
		__CPROVER_assert(ret == -EBADMSG && !verified,
				 "an unparseable signature checks nothing");
		return;
	}
	__CPROVER_assert(ret || (verified && hashed_data == attest &&
				 hashed_len == attest_len),
			 "passes only on the digest of the whole attestation");
	__CPROVER_assert(ret != -EINVAL, "a rejection is -EKEYREJECTED");
}

void harness(void)
{
	signer();
	signature();
}
