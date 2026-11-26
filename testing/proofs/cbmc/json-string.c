// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The string reader of util/json.c on every input of LEN bytes and every
 * buffer of up to LEN bytes: it takes exactly a string of ECMA-404 under
 * json.h's restrictions, decodes it into the buffer when it fits and
 * reports -ENOSPC when not, and writes nothing past the buffer.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

static bool in(__s64 c, __s64 lo, __s64 hi)
{
	return c >= lo && c <= hi;
}

/* Table 3-7 of the Unicode Standard, row by row. */
static size_t table_width(const __u8 *s, size_t n)
{
	if (n >= 1 && s[0] <= 0x7f)
		return 1;
	if (n >= 2 && in(s[0], 0xc2, 0xdf) && in(s[1], 0x80, 0xbf))
		return 2;
	if (n >= 3 && in(s[2], 0x80, 0xbf) &&
	    ((s[0] == 0xe0 && in(s[1], 0xa0, 0xbf)) ||
	     (in(s[0], 0xe1, 0xec) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xed && in(s[1], 0x80, 0x9f)) ||
	     (in(s[0], 0xee, 0xef) && in(s[1], 0x80, 0xbf))))
		return 3;
	if (n >= 4 && in(s[2], 0x80, 0xbf) && in(s[3], 0x80, 0xbf) &&
	    ((s[0] == 0xf0 && in(s[1], 0x90, 0xbf)) ||
	     (in(s[0], 0xf1, 0xf3) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xf4 && in(s[1], 0x80, 0x8f))))
		return 4;
	return 0;
}

static int hex_value(__u8 c)
{
	if (in(c, '0', '9'))
		return c - '0';
	if (in(c, 'a', 'f'))
		return c - 'a' + 10;
	if (in(c, 'A', 'F'))
		return c - 'A' + 10;
	return -1;
}

/* The code unit of \uXXXX at t[i], or -1. */
static int code_unit(const __u8 *t, size_t n, size_t i)
{
	int cu = 0, h, j;

	if (i + 6 > n || t[i] != '\\' || t[i + 1] != 'u')
		return -1;
	for (j = 2; j < 6; j++) {
		h = hex_value(t[i + j]);
		if (h < 0)
			return -1;
		cu = cu * 16 + h;
	}
	return cu;
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

/*
 * The string of ECMA-404, section 9, that t starts with, decoded into out,
 * and its length in *end: no \u0000, no lone surrogate escape and nothing
 * but well-formed UTF-8 between the quotes.
 */
static bool json_string(const __u8 *t, size_t n, __u8 *out, size_t *len,
			size_t *end)
{
	static const char plain[] = "\"\\/bfnrt", value[] = "\"\\/\b\f\n\r\t";
	size_t i = 1, k = 0, w;
	const char *q;
	int cu, lo;

	if (!n || t[0] != '"')
		return false;
	while (i < n && t[i] != '"') {
		if (t[i] < 0x20)
			return false;
		if (t[i] != '\\') {
			w = table_width(t + i, n - i);
			if (!w)
				return false;
			memcpy(out + k, t + i, w);
			k += w;
			i += w;
			continue;
		}
		q = i + 1 < n ? memchr(plain, t[i + 1], sizeof(plain) - 1) : NULL;
		if (q) {
			out[k++] = value[q - plain];
			i += 2;
			continue;
		}
		cu = code_unit(t, n, i);
		if (cu <= 0 || in(cu, 0xdc00, 0xdfff))
			return false;
		i += 6;
		if (in(cu, 0xd800, 0xdbff)) {
			lo = code_unit(t, n, i);
			if (!in(lo, 0xdc00, 0xdfff))
				return false;
			cu = 0x10000 + (cu - 0xd800) * 1024 + lo - 0xdc00;
			i += 6;
		}
		k += utf8(cu, out + k);
	}
	if (i == n)
		return false;
	*len = k;
	*end = i + 1;
	return true;
}

void harness(void)
{
	char buf[LEN + 1], was[LEN + 1], *dst;
	size_t cap, want_len, end, i;
	__u8 want[LEN + 1];
	struct pctx c = {};
	const char *s;
	bool discard;
	int ret;

	s = any_bytes(LEN);
	c.p = s;
	c.end = s + LEN;
	__CPROVER_assume(cap >= 1 && cap <= sizeof(buf));
	memcpy(was, buf, sizeof(buf));
	dst = discard ? NULL : buf;
	ret = parse_string(&c, dst, cap);
	for (i = cap; i < sizeof(buf); i++)
		__CPROVER_assert(buf[i] == was[i], "nothing written past cap");
	if (!json_string((const __u8 *)s, LEN, want, &want_len, &end)) {
		__CPROVER_assert(ret == -EINVAL || (!discard && ret == -ENOSPC),
				 "no string refused");
		return;
	}
	__CPROVER_assert(!ret == (discard || want_len < cap) &&
			 (!ret || ret == -ENOSPC),
			 "a string taken when it fits");
	if (ret)
		return;
	__CPROVER_assert(c.p == s + end, "and nothing past it");
	if (!discard)
		__CPROVER_assert(!memcmp(dst, want, want_len) &&
				 !dst[want_len], "decoded and terminated");
}
