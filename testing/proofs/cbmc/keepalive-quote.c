// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * keepalive_quote_format() of util/keepalive_quote.c, the quote a
 * keepalive carries and the backend's checker splits, for every outcome of
 * its three encodings and a room of LEN bytes: exactly
 * "attest=<a>;sig=<s>;ak=<k>" with its terminator when it fits, -E2BIG
 * with nothing written when it does not, and the first encoding's error
 * when one fails. base64_encode() is OpenSSL's; the stub here encodes each
 * of the three as one letter after it checks what it is handed.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/keepalive_quote.c"
#include "../../../util/string.c"

#define QUOTE	"attest=a;sig=b;ak=c"

static const struct tpm_attestation *att;
static const struct tpm_key *ak;
static int fails[3], calls;

int base64_encode(const __u8 *data, size_t len, char *out, size_t out_sz)
{
	static const size_t room[] = {
		BASE64_SIZE(TPM_ATTEST_MAX), BASE64_SIZE(TPM_SIGNATURE_MAX),
		BASE64_SIZE(TPM_PUBLIC_MAX),
	};
	const __u8 *const from[] = { att->attest, att->signature, ak->public };
	const size_t lens[] = { att->attest_len, att->signature_len,
				ak->public_len };
	int k = calls++;

	__CPROVER_assert(k < 3 && data == from[k] && len == lens[k] &&
			 out_sz == room[k],
			 "each part encoded from its field into all its room");
	if (fails[k])
		return fails[k];
	out[0] = (char)('a' + k);
	out[1] = '\0';
	return 0;
}

void harness(void)
{
	struct tpm_attestation any_att;
	struct tpm_key any_ak;
	int any_fails[3], k, ret, failed = 0;
	const size_t room = LEN;
	size_t i;
	char *out;

	att = &any_att;
	ak = &any_ak;
	for (k = 0; k < 3; k++) {
		fails[k] = any_fails[k];
		__CPROVER_assume(fails[k] <= 0);
		if (!failed)
			failed = fails[k];
	}
	out = any_bytes(LEN);
	ret = keepalive_quote_format(att, ak, out, LEN);
	if (failed) {
		__CPROVER_assert(ret == failed,
				 "the first failed encoding's error");
		return;
	}
	if (room < sizeof(QUOTE)) {
		__CPROVER_assert(ret == -E2BIG && !out[0],
				 "-E2BIG when it does not fit, nothing written");
		return;
	}
	__CPROVER_assert(!ret, "the quote written");
	for (i = 0; i < sizeof(QUOTE); i++)
		__CPROVER_assert(out[i] == QUOTE[i],
				 "attest=, sig= and ak= with their parts");
}
