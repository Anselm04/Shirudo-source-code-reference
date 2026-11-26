// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The TPM structures in a target's evidence: key public areas and their
 * names, quote and certification attestations and their signatures.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/byteorder.h>

#include "fuzz.h"
#include "tpm_wire.h"

static bool within(const __u8 *p, size_t n, const __u8 *data, size_t size)
{
	return p >= data && n <= size && (size_t)(p - data) <= size - n;
}

/*
 * What parses holds to what the parsers promise: a public area
 * marshals back to the bytes it came from, it has a name exactly when
 * its name algorithm is SHA-256, the ECC parser takes a subset of it,
 * a signature is the one fixed size, and an attestation points only
 * into the input.
 */
int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	__u8 name[TPM_NAME_LEN], r[32], s[32], again[1024];
	struct tpm_ecc_public ecc;
	struct tpm_public pub;
	struct tpm_attest at;
	bool parsed, named;
	size_t len;

	parsed = !tpm_public_parse(data, size, &pub);
	named = !tpm_object_name(data, size, name);
	if (named != (size >= 4 && get_be16(data + 2) == TPM_ALG_SHA256))
		abort();
	if (parsed &&
	    (!named || tpm_public_marshal(&pub, again, sizeof(again), &len) ||
	     len != size || memcmp(again, data, size)))
		abort();
	if (!tpm_ecc_public_parse(data, size, &ecc) &&
	    (!parsed || pub.type != TPM_ALG_ECC))
		abort();
	if (!tpm_ecdsa_signature_parse(data, size, r, s) && size != 72)
		abort();
	if (!tpm_attest_parse(data, size, &at) &&
	    (at.signer_len > TPM_NAME_LEN ||
	     !within(at.extra, at.extra_len, data, size) ||
	     (at.type == TPM_ST_ATTEST_NV &&
	      (at.index_name_len > TPM_NAME_LEN ||
	       !within(at.nv_data, at.nv_len, data, size)))))
		abort();
	return 0;
}
