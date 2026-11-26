// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tpm_ecdsa_signature_parse() of util/tpm_wire.c, on the signatures of
 * evidence, for inputs of every size: it reads nothing past its input and
 * accepts exactly a TPMT_SIGNATURE of ECDSA over SHA-256 with 32-byte r and
 * s, which it returns as they stand.
 */

#include "proof.h"
#include "../../../util/tpm_wire.c"

#define SIG_LEN	(2u + 2 + 2 + 32 + 2 + 32)

static bool bytes_at(const __u8 *a, const __u8 *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

void harness(void)
{
	__u8 r[32], s[32];
	bool well_formed;
	size_t len;
	__u8 *buf;
	int ret;

	buf = any_bytes(min(len, SIG_LEN));
	ret = tpm_ecdsa_signature_parse(buf, len, r, s);
	if (len != SIG_LEN) {
		__CPROVER_assert(ret, "nothing but the signature");
		return;
	}
	well_formed = get_be16(buf) == TPM_ALG_ECDSA &&
		      get_be16(buf + 2) == TPM_ALG_SHA256 &&
		      get_be16(buf + 4) == 32 && get_be16(buf + 38) == 32;
	__CPROVER_assert(!ret == well_formed,
			 "accepts exactly ECDSA, SHA-256, 32-byte r and s");
	if (!ret)
		__CPROVER_assert(bytes_at(r, buf + 6, 32) &&
				 bytes_at(s, buf + 40, 32),
				 "r and s as the signature holds them");
}
