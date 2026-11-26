// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "keepalive_quote.h"
#include "unit.h"

static void quote_is_the_three_fields_in_base64(void)
{
	struct tpm_attestation att = {
		.attest = { 0xff, 0x54, 0x43 },
		.attest_len = 3,
		.signature = { 0x00, 0x18 },
		.signature_len = 2,
	};
	struct tpm_key ak = {
		.public = { 0x00, 0x23, 0x00, 0x0b },
		.public_len = 4,
	};
	char out[KEEPALIVE_QUOTE_MAX];

	ASSERT_EQ(keepalive_quote_format(&att, &ak, out, sizeof(out)), 0);
	EXPECT_STREQ(out, "attest=/1RD;sig=ABg=;ak=ACMACw==");
}

static void quote_of_the_largest_fields_fits(void)
{
	struct tpm_attestation att = {
		.attest_len = TPM_ATTEST_MAX,
		.signature_len = TPM_SIGNATURE_MAX,
	};
	struct tpm_key ak = { .public_len = TPM_PUBLIC_MAX };
	char out[KEEPALIVE_QUOTE_MAX];

	ASSERT_EQ(keepalive_quote_format(&att, &ak, out, sizeof(out)), 0);
	EXPECT_UEQ(strlen(out) + 1, KEEPALIVE_QUOTE_MAX - 3);
}

static void quote_refuses_a_buffer_one_byte_short(void)
{
	struct tpm_attestation att = {
		.attest = { 0xff, 0x54, 0x43 },
		.attest_len = 3,
		.signature = { 0x00, 0x18 },
		.signature_len = 2,
	};
	struct tpm_key ak = {
		.public = { 0x00, 0x23, 0x00, 0x0b },
		.public_len = 4,
	};
	const char *want = "attest=/1RD;sig=ABg=;ak=ACMACw==";
	char out[64];

	EXPECT_EQ(keepalive_quote_format(&att, &ak, out, strlen(want)),
		  -E2BIG);
	EXPECT_EQ(keepalive_quote_format(&att, &ak, out, strlen(want) + 1),
		  0);
	EXPECT_STREQ(out, want);
}

static const struct unit_case cases[] = {
	UNIT_CASE(quote_is_the_three_fields_in_base64),
	UNIT_CASE(quote_of_the_largest_fields_fits),
	UNIT_CASE(quote_refuses_a_buffer_one_byte_short),
	{}
};

UNIT_SUITE(keepalive_quote, cases);
