// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * parse_u64() and parse_x64() of util/string.c against the model that
 * testing/proofs/lean4/Shirudo/Number.lean proves exact for every length:
 * on every string of up to LEN_MAX bytes they yield the model's value, or
 * -ERANGE exactly where the model refuses.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define LEN_MAX	4	/* short enough that no step reaches 2^64 */

static int model_digit(char c, bool hex)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (hex && c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (hex && c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void against_model(bool hex)
{
	__u64 max, out, v = 0;
	bool digits = true, within = true;
	size_t len, i;
	char *s;
	int ret;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_bytes(len);
	for (i = 0; i < len; i++) {
		int d = model_digit(s[i], hex);

		if (d < 0) {
			digits = false;
			continue;
		}
		v = v * (hex ? 16 : 10) + (__u64)d;
		if (v > max)
			within = false;
	}
	ret = hex ? parse_x64(s, len, max, &out) : parse_u64(s, len, max, &out);
	if (!len || !digits)
		return;
	__CPROVER_assert(within ? !ret && out == v : ret == -ERANGE,
			 "the model's value, or -ERANGE where it refuses");
}

void harness(void)
{
	against_model(false);
	against_model(true);
}
