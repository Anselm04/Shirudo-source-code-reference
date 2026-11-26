// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tpm_public_parse() and tpm_ecc_public_parse() of util/tpm_wire.c, on the
 * key public areas of evidence, for inputs of every size: they read nothing
 * outside the input and accept only the P-256 and RSA-2048 shapes they
 * name, spanning the whole input.
 */

#include "proof.h"
#include "../../../util/tpm_wire.c"

/* The longest: a policy, a protector, a scheme and an RSA modulus. */
#define PUBLIC_MAX	(14 + 32 + 4 + 2 + 8 + 256)

/*
 * LEN picks the parser: 0 tpm_public_parse(), 1 tpm_ecc_public_parse(),
 * which calls it. Both in one run take 7 GB, more than CI gives a proof.
 */
#define ECC_PARSE	(LEN == 1)

static bool shape(const struct tpm_public *p)
{
	return (p->policy_len == 0 || p->policy_len == 32) &&
	       (p->sym_alg == TPM_ALG_NULL ||
		(p->sym_alg == TPM_ALG_AES && p->sym_bits == 128 &&
		 p->sym_mode == TPM_ALG_CFB)) &&
	       (p->scheme == TPM_ALG_NULL ||
		(p->scheme == TPM_ALG_ECDSA &&
		 p->scheme_hash == TPM_ALG_SHA256)) &&
	       ((p->type == TPM_ALG_ECC && p->curve == TPM_ECC_NIST_P256) ||
		(p->type == TPM_ALG_RSA && p->rsa_bits == 2048 &&
		 p->n_len == 256 &&
		 (!p->rsa_exponent || p->rsa_exponent == 65537)));
}

static size_t wire_len(const struct tpm_public *p)
{
	return 14 + p->policy_len +
	       (p->sym_alg != TPM_ALG_NULL ? 4 : 0) +
	       (p->scheme != TPM_ALG_NULL ? 2 : 0) +
	       (p->type == TPM_ALG_ECC ? 72 : 8 + p->n_len);
}

void harness(void)
{
	struct tpm_ecc_public ecc;
	struct tpm_public p;
	const __u8 *buf;
	size_t len;

	buf = any_input(len, PUBLIC_MAX);
	if (!ECC_PARSE) {
		if (!tpm_public_parse(buf, len, &p))
			__CPROVER_assert(shape(&p) && len == wire_len(&p),
					 "a key of the shapes it names, the whole input");
		return;
	}
	if (!tpm_ecc_public_parse(buf, len, &ecc))
		__CPROVER_assert(ecc.curve == TPM_ECC_NIST_P256 &&
				 ecc.scheme == TPM_ALG_ECDSA &&
				 ecc.hash == TPM_ALG_SHA256,
				 "a P-256 ECDSA key over SHA-256");
}
