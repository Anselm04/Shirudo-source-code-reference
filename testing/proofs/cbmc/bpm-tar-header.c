// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_tar_header_ok() of util/bpm_package.c: every 512-byte header with a
 * checksum field that is not octal fails, and a header of any bytes in a
 * WINDOW at LEN and in its checksum field, zero elsewhere, passes exactly
 * when the field holds its byte sum, the field's own bytes as blanks.
 */

#include "proof.h"
#include "../../../util/bpm_package.c"

#define TAR_HEADER	512
#define CHKSUM_OFF	148
#define CHKSUM_LEN	8
#define WINDOW		64

static bool in_field(size_t i)
{
	return i >= CHKSUM_OFF && i < CHKSUM_OFF + CHKSUM_LEN;
}

static void any_header(void)
{
	__u64 want;
	__u8 *h;

	h = any_bytes(TAR_HEADER);
	if (bpm_tar_octal((const char *)h + CHKSUM_OFF, CHKSUM_LEN, &want))
		__CPROVER_assert(!bpm_tar_header_ok(h),
				 "a checksum field not octal fails");
}

static void windowed_header(void)
{
	__u64 want, sum = CHKSUM_LEN * ' ';
	size_t i;
	__u8 *h;

	h = any_bytes(TAR_HEADER);
	for (i = 0; i < TAR_HEADER; i++) {
		if (in_field(i))
			continue;
		if (i >= LEN && i < LEN + WINDOW)
			sum += h[i];
		else
			__CPROVER_assume(!h[i]);
	}
	if (bpm_tar_octal((const char *)h + CHKSUM_OFF, CHKSUM_LEN, &want))
		return;
	__CPROVER_assert(bpm_tar_header_ok(h) == (want == sum),
			 "a header passes exactly when its checksum matches");
}

void harness(void)
{
	any_header();
	windowed_header();
}
