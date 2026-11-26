// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A target's evidence as the operator verifies it and makes a credential
 * challenge from it, and the challenge as the target reads it back.
 */

#include "attest.h"
#include "fuzz.h"
#include "malloc.h"

static const __u8 nonce[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct attest_challenge_policy pol = {
		.trust_presented = true,
	};
	struct attest_expect expect = {
		.nonce = nonce,
		.nonce_len = sizeof(nonce),
		.allow_runtime_events = true,
	};
	struct attest_challenge challenge;
	__u8 credential[TPM_CREDENTIAL_LEN];
	size_t out_len, cap;
	char report[4096];
	char path[64];
	char *out;
	int fd;

	attest_verify((const char *)data, size, &expect, report,
		      sizeof(report));
	if (!attest_challenge_make((const char *)data, size, &pol,
				   credential, &out, &out_len, &cap,
				   report, sizeof(report)))
		xfree(out, cap);
	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	attest_challenge_read(path, &challenge);
	close(fd);
	return 0;
}
