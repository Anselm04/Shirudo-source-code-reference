// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tpm_attest_parse() of util/tpm_wire.c, which attest verify runs on the
 * quote and certification a target sends, for inputs of every size: it
 * reads nothing outside them, what it accepts is a quote or an NV
 * certification spanning the whole input, and each field is the bytes at
 * its place.
 */

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/tpm_wire.c"

/* An NV certification of the longest names, extra data and contents. */
#define ATTEST_MAX	(4u + 2 + 2 + 34 + 2 + 64 + 27 + 2 + 34 + 2 + 2 + 2048)

static bool bytes_at(const __u8 *a, const __u8 *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

static __u64 be64_at(const __u8 *p)
{
	return (__u64)get_be32(p) << 32 | get_be32(p + 4);
}

/* TPMS_CLOCK_INFO and the firmware version, after the extra data. */
static void clock_read(const struct tpm_attest *a, const __u8 *at)
{
	__CPROVER_assert(a->clock == be64_at(at) &&
			 a->reset_count == get_be32(at + 8) &&
			 a->restart_count == get_be32(at + 12) &&
			 a->safe == (at[16] != 0) &&
			 a->firmware_version == be64_at(at + 17),
			 "the clock, counts and firmware as the TPM wrote them");
}

/* TPMS_QUOTE_INFO: one SHA-256 selection of three bytes, then the digest. */
static void quote_read(const struct tpm_attest *a, const __u8 *at)
{
	__CPROVER_assert(a->pcr_mask == ((__u32)at[7] | (__u32)at[8] << 8 |
					 (__u32)at[9] << 16),
			 "the PCRs its selection names");
	__CPROVER_assert(get_be16(at + 10) == 32 &&
			 bytes_at(a->pcr_digest, at + 12, 32),
			 "the digest it signs");
}

void harness(void)
{
	size_t len, head, extra_at;
	struct tpm_attest a;
	const __u8 *buf;

	buf = any_bytes(min(len, ATTEST_MAX));
	if (tpm_attest_parse(buf, len, &a))
		return;
	__CPROVER_assert(get_be32(buf) == TPM_GENERATED &&
			 a.type == get_be16(buf + 4), "TPM-generated, its type");
	__CPROVER_assert(a.signer_len <= TPM_NAME_LEN &&
			 a.signer_len == get_be16(buf + 6) &&
			 bytes_at(a.signer, buf + 8, a.signer_len),
			 "the signer's name as the TPM wrote it");
	extra_at = 8 + a.signer_len + 2;
	__CPROVER_assert(a.extra_len <= 64 && a.extra == buf + extra_at,
			 "extra data inside the input, at its place");
	clock_read(&a, buf + extra_at + a.extra_len);
	head = extra_at + a.extra_len + 8 + 4 + 4 + 1 + 8;
	if (a.type == TPM_ST_ATTEST_QUOTE) {
		__CPROVER_assert(len == head + 4 + 2 + 1 + TPM_PCR_SELECT_LEN +
				 2 + 32, "a quote spans the whole input");
		quote_read(&a, buf + head);
		return;
	}
	__CPROVER_assert(a.type == TPM_ST_ATTEST_NV, "a quote or an NV one");
	__CPROVER_assert(a.index_name_len <= TPM_NAME_LEN &&
			 a.index_name_len == get_be16(buf + head) &&
			 bytes_at(a.index_name, buf + head + 2,
				  a.index_name_len),
			 "the index's name as the TPM wrote it");
	__CPROVER_assert(a.offset == get_be16(buf + head + 2 +
					      a.index_name_len),
			 "the offset certified");
	__CPROVER_assert(a.nv_len <= 2048 &&
			 len == head + 2 + a.index_name_len + 2 + 2 +
				a.nv_len &&
			 a.nv_data == buf + len - a.nv_len,
			 "the NV contents end the input");
}
