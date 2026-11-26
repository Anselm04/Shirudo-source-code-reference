// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * util/hex.c for every input of up to LEN_MAX bytes: an encoding is
 * lowercase hex that decodes back to its input, allocated or not, a
 * decode takes exactly 2 * n hex digits of either case and yields their
 * value, and one of at most cap bytes any even count of them up to
 * 2 * cap, reading no further than the digit after those.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/hex.c"

#define LEN_MAX	4

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

static void encoded(void)
{
	__u8 *in, *back;
	size_t n, i;
	char *out;

	__CPROVER_assume(n <= LEN_MAX);
	in = any_bytes(n);
	out = any_bytes(2 * n + 1);
	back = any_bytes(n);
	hex_encode(in, n, out);
	__CPROVER_assert(!out[2 * n], "terminated");
	for (i = 0; i < 2 * n; i++)
		__CPROVER_assert((out[i] >= '0' && out[i] <= '9') ||
				 (out[i] >= 'a' && out[i] <= 'f'),
				 "lowercase hex digits");
	__CPROVER_assert(!hex_decode(out, back, n) && !memcmp(back, in, n),
			 "decodes back to its input");
}

static void allocated(void)
{
	__u8 *in, *back;
	char *out;
	size_t n;

	__CPROVER_assume(n <= LEN_MAX);
	in = any_bytes(n);
	back = any_bytes(n);
	out = hex_alloc(in, n);
	if (!out)
		return;
	__CPROVER_assert(strlen(out) == 2 * n, "2 * n digits, terminated");
	__CPROVER_assert(!hex_decode(out, back, n) && !memcmp(back, in, n),
			 "decodes back to its input");
	xfree(out, 2 * n + 1);
}

static void decoded(void)
{
	size_t len, n, i;
	bool hex = true;
	char *s;
	__u8 *out;
	int ret;

	__CPROVER_assume(len <= 2 * LEN_MAX + 1 && n <= LEN_MAX);
	s = any_bytes(len + 1);
	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	out = any_bytes(n);
	ret = hex_decode(s, out, n);
	for (i = 0; i < len; i++)
		if (digit(s[i]) < 0)
			hex = false;
	__CPROVER_assert(!ret || ret == -EINVAL, "0 or -EINVAL");
	__CPROVER_assert(!ret == (len == 2 * n && hex),
			 "exactly 2 * n hex digits");
	for (i = 0; !ret && i < n; i++)
		__CPROVER_assert(out[i] == digit(s[2 * i]) * 16 +
					    digit(s[2 * i + 1]),
				 "the value of each pair");
}

static void decoded_max(void)
{
	size_t len, cap, n, i;
	bool hex = true;
	char *s;
	__u8 *out;
	int ret;

	__CPROVER_assume(len <= 2 * LEN_MAX + 1 && cap <= LEN_MAX);
	s = any_bytes(len + 1);
	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	out = any_bytes(cap);
	ret = hex_decode_max(s, out, cap, &n);
	for (i = 0; i < len; i++)
		if (digit(s[i]) < 0)
			hex = false;
	__CPROVER_assert(!ret || ret == -EINVAL, "0 or -EINVAL");
	__CPROVER_assert(!ret == (len % 2 == 0 && len / 2 <= cap && hex),
			 "an even count of hex digits, at most 2 * cap");
	__CPROVER_assert(ret || n == len / 2, "half as many bytes");
	for (i = 0; !ret && i < n; i++)
		__CPROVER_assert(out[i] == digit(s[2 * i]) * 16 +
					    digit(s[2 * i + 1]),
				 "the value of each pair");
}

static void decoded_max_unterminated(void)
{
	size_t cap, n;
	__u8 *out;
	char *s;

	__CPROVER_assume(cap <= LEN_MAX);
	s = any_bytes(2 * cap + 1);
	out = any_bytes(cap);
	__CPROVER_assume(!memchr(s, '\0', 2 * cap + 1));
	__CPROVER_assert(hex_decode_max(s, out, cap, &n) == -EINVAL,
			 "too long, read no further than 2 * cap + 1");
}

void harness(void)
{
	encoded();
	allocated();
	decoded();
	decoded_max();
	decoded_max_unterminated();
}
