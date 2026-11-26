// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The \u escapes of util/json.c for every pair of code units, spelled in
 * either case: two characters, or one from a surrogate pair, become their
 * UTF-8, and \u0000 and a lone surrogate are refused.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

static bool in(__u32 c, __u32 lo, __u32 hi)
{
	return c >= lo && c <= hi;
}

static void spell(char *out, __u16 cu)
{
	int i;

	out[0] = '\\';
	out[1] = 'u';
	for (i = 0; i < 4; i++) {
		__u8 d = cu >> (12 - 4 * i) & 15;
		bool upper;

		out[2 + i] = d < 10 ? '0' + d : (upper ? 'A' : 'a') + d - 10;
	}
}

/* A scalar value as UTF-8, Table 3-6. */
static size_t utf8(__u32 cp, __u8 *out)
{
	if (cp < 0x80) {
		out[0] = cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = 0xc0 + cp / 64;
		out[1] = 0x80 + cp % 64;
		return 2;
	}
	if (cp < 0x10000) {
		out[0] = 0xe0 + cp / 4096;
		out[1] = 0x80 + cp / 64 % 64;
		out[2] = 0x80 + cp % 64;
		return 3;
	}
	out[0] = 0xf0 + cp / 262144;
	out[1] = 0x80 + cp / 4096 % 64;
	out[2] = 0x80 + cp / 64 % 64;
	out[3] = 0x80 + cp % 64;
	return 4;
}

static bool character(__u16 cu)
{
	return cu && !in(cu, 0xd800, 0xdfff);
}

void harness(void)
{
	__u8 want[8], dst[8];
	struct pctx c = {};
	size_t want_len;
	char text[14];
	__u16 hi, lo;
	bool pair;
	int ret;

	text[0] = '"';
	spell(text + 1, hi);
	spell(text + 7, lo);
	text[13] = '"';
	c.p = text;
	c.end = text + sizeof(text);
	ret = parse_string(&c, (char *)dst, sizeof(dst));
	pair = in(hi, 0xd800, 0xdbff) && in(lo, 0xdc00, 0xdfff);
	if (!pair && !(character(hi) && character(lo))) {
		__CPROVER_assert(ret == -EINVAL,
				 "\\u0000 and a lone surrogate refused");
		return;
	}
	if (pair) {
		want_len = utf8(0x10000 + (hi - 0xd800) * 1024 + lo - 0xdc00,
				want);
	} else {
		want_len = utf8(hi, want);
		want_len += utf8(lo, want + want_len);
	}
	__CPROVER_assert(!ret && c.p == c.end, "the string taken");
	__CPROVER_assert(!memcmp(dst, want, want_len) && !dst[want_len],
			 "as the UTF-8 of its characters");
}
