// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The string writer of util/json.c on every string of LEN bytes: it writes
 * one JSON string of ECMA-404 in well-formed UTF-8 that decodes to the
 * input, or lossy to it with U+FFFD for each NUL and ill-formed byte, and
 * strict refuses exactly the input that is no NUL-free well-formed UTF-8.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

#define OUT_MAX	(6 * LEN + 3)

static bool in(__u8 c, __u8 lo, __u8 hi)
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

static bool well_formed(const __u8 *s, size_t n)
{
	size_t i, w;

	for (i = 0; i < n; i += w) {
		w = table_width(s + i, n - i);
		if (!w)
			return false;
	}
	return true;
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

/* A code point of the Basic Multilingual Plane as UTF-8, Table 3-6. */
static size_t bmp_utf8(__u32 cp, __u8 *out)
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
	out[0] = 0xe0 + cp / 4096;
	out[1] = 0x80 + cp / 64 % 64;
	out[2] = 0x80 + cp % 64;
	return 3;
}

/*
 * The n bytes at t as one string of ECMA-404, section 9, with no
 * surrogate escape, decoded into out.
 */
static bool json_string(const __u8 *t, size_t n, __u8 *out, size_t *len)
{
	static const char plain[] = "\"\\/bfnrt", value[] = "\"\\/\b\f\n\r\t";
	size_t i = 1, k = 0, j;
	const char *q;
	__u32 cp;
	__u8 c;
	int h;

	if (n < 2 || t[0] != '"' || t[n - 1] != '"')
		return false;
	while (i < n - 1) {
		c = t[i++];
		if (c == '"' || c < 0x20)
			return false;
		if (c != '\\') {
			out[k++] = c;
			continue;
		}
		if (i == n - 1)
			return false;
		c = t[i++];
		q = memchr(plain, c, sizeof(plain) - 1);
		if (q) {
			out[k++] = value[q - plain];
			continue;
		}
		if (c != 'u' || n - 1 - i < 4)
			return false;
		for (cp = 0, j = 0; j < 4; j++) {
			h = hex_value(t[i++]);
			if (h < 0)
				return false;
			cp = cp * 16 + h;
		}
		if (cp >= 0xd800 && cp <= 0xdfff)
			return false;
		k += bmp_utf8(cp, out + k);
	}
	*len = k;
	return true;
}

/* The input with U+FFFD for each NUL and each byte no character starts. */
static size_t replaced(const __u8 *s, size_t n, __u8 *out)
{
	size_t i, k = 0, w;

	for (i = 0; i < n; i += w) {
		w = s[i] ? table_width(s + i, n - i) : 0;
		if (!w) {
			k += bmp_utf8(0xfffd, out + k);
			w = 1;
			continue;
		}
		memcpy(out + k, s + i, w);
		k += w;
	}
	return k;
}

void harness(void)
{
	__u8 want[3 * LEN + 1], got[OUT_MAX];
	struct json_emit e = {};
	size_t want_len, got_len;
	bool lossy, ok;
	const __u8 *s;

	s = any_bytes(LEN);
	e.buf = any_bytes(OUT_MAX);
	e.cap = OUT_MAX;
	put_string_n(&e, (const char *)s, LEN, lossy);
	ok = well_formed(s, LEN) && !memchr(s, '\0', LEN);
	__CPROVER_assert(e.err == (ok || lossy ? 0 : -EILSEQ),
			 "strict refuses exactly NUL and ill-formed UTF-8");
	if (e.err)
		return;
	__CPROVER_assert(e.len < e.cap && !e.buf[e.len], "terminated output");
	__CPROVER_assert(well_formed((const __u8 *)e.buf, e.len),
			 "well-formed UTF-8 output");
	__CPROVER_assert(json_string((const __u8 *)e.buf, e.len, got,
				     &got_len),
			 "one JSON string");
	want_len = lossy ? replaced(s, LEN, want) : LEN;
	__CPROVER_assert(got_len == want_len &&
			 !memcmp(got, lossy ? want : s, want_len),
			 "which decodes to the input");
}
