// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The packed fields of util/keepalive.c that the backend reads bit by bit:
 * the mask of LEN outcome codes and the conditions word.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/keepalive.c"

static __u8 packed[KEEPALIVE_MASK_BYTES];
static size_t packed_len;

/* OpenSSL encodes; the proof keeps the bytes it is handed. */
int base64_encode(const __u8 *data, size_t len, char *out, size_t out_sz)
{
	__CPROVER_assert(len <= sizeof(packed), "no more than a full mask");
	memcpy(packed, data, len);
	packed_len = len;
	return 0;
}

static void mask(void)
{
	__u8 codes[LEN ? LEN : 1];
	char b64[KEEPALIVE_MASK_B64_MAX];
	size_t n = LEN, bytes = (n + 3) / 4, cap;
	bool valid = true;
	int ret;

	__CPROVER_assume(cap <= sizeof(b64));
	for (size_t i = 0; i < LEN; i++)
		valid = valid && codes[i] <= 3;
	ret = keepalive_mask(codes, LEN, b64, cap);
	if (n > KEEPALIVE_MASK_OPS || !valid) {
		__CPROVER_assert(ret == -EINVAL,
				 "a window too long or a code past two bits");
		return;
	}
	if (cap < 4 * ((bytes + 2) / 3) + 1) {
		__CPROVER_assert(ret == -E2BIG, "a buffer too small");
		return;
	}
	__CPROVER_assert(!ret && packed_len == bytes, "every code packed");
	for (size_t i = 0; i < LEN; i++)
		__CPROVER_assert(((packed[i / 4] >> (6 - 2 * (i % 4))) & 3) ==
				 codes[i], "the first code in the highest bits");
	if (LEN % 4)
		__CPROVER_assert(!(packed[bytes - 1] & (0xff >> (2 * (LEN % 4)))),
				 "the last byte padded with zeros");
}

static const char *const types[] = {
	"LsmAttached", "KeyringSealed", "ChainIntact", "UpatchesMeasured",
	"TpmMeasured", "ConfigActive", "XdpCovered", "Unknown",
};

static const char *const statuses[] = { "", "OK", "WARN", "ALERT", "?" };

static void cond(void)
{
	struct condition conds[CONDITIONS_MAX];
	size_t type[CONDITIONS_MAX], status[CONDITIONS_MAX], n;
	__u16 word;

	__CPROVER_assume(n <= CONDITIONS_MAX);
	for (size_t i = 0; i < n; i++) {
		__CPROVER_assume(type[i] < ARRAY_SIZE(types));
		__CPROVER_assume(status[i] < ARRAY_SIZE(statuses));
		conds[i].type = types[type[i]];
		conds[i].status = statuses[status[i]];
	}
	word = keepalive_cond(conds, n);
	for (size_t k = 0; k < CONDITIONS_MAX; k++) {
		size_t want = 0;

		for (size_t i = n; i-- > 0;) {
			if (type[i] == k)
				want = status[i] <= 3 ? status[i] : 0;
		}
		__CPROVER_assert(((word >> (2 * k)) & 3) == want,
				 "each pair by its type name, the first given");
	}
	__CPROVER_assert(!(word >> (2 * CONDITIONS_MAX)),
			 "no pair past the conditions");
}

void harness(void)
{
	mask();
	if (!LEN)
		cond();
}
