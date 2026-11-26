// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * sha256_digest_decode() of util/hex.c for every string of LEN bytes: it
 * takes "sha256:" and exactly 64 hex digits of either case, yields their
 * value, and refuses a null pointer.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/hex.c"

#define PREFIX	7
#define DIGITS	64

static int digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

void harness(void)
{
	bool tagged, hex = true;
	size_t i, len = LEN;
	__u8 out[32];
	char *s;
	int ret;

	__CPROVER_assert(sha256_digest_decode(NULL, out) == -EINVAL,
			 "no string, no digest");
	s = any_bytes(len + 1);
	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	ret = sha256_digest_decode(s, out);
	tagged = len >= PREFIX && !memcmp(s, "sha256:", PREFIX);
	for (i = PREFIX; i < len; i++)
		if (digit(s[i]) < 0)
			hex = false;
	__CPROVER_assert(!ret || ret == -EINVAL, "0 or -EINVAL");
	__CPROVER_assert(!ret == (tagged && len == PREFIX + DIGITS && hex),
			 "the tag and exactly 64 hex digits");
	for (i = 0; !ret && i < sizeof(out); i++)
		__CPROVER_assert(out[i] == digit(s[PREFIX + 2 * i]) * 16 +
					    digit(s[PREFIX + 2 * i + 1]),
				 "the value of each pair");
}
