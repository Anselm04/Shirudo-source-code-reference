// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * util/hex.c against the model testing/proofs/lean4/Shirudo/Hex.lean
 * proves for every length: on every input of up to LEN_MAX bytes, and for
 * counts and capacities small and past SIZE_MAX / 2, hex_encode(),
 * hex_decode() and hex_decode_max() compute encode, decode and decodeMax.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/hex.c"

#define LEN_MAX	8

static const char model_table[] = "0123456789abcdef";

static size_t model_size_mul(size_t a, size_t b)
{
	size_t r;

	return check_mul_overflow(a, b, &r) ? SIZE_MAX : r;
}

static size_t model_size_add(size_t a, size_t b)
{
	size_t r;

	return check_add_overflow(a, b, &r) ? SIZE_MAX : r;
}

/* nibble, with -1 for none. */
static int model_nibble(__u8 c)
{
	if (c >= 0x30 && c <= 0x39)
		return c - 0x30;
	if (c >= 0x61 && c <= 0x66)
		return c - 0x61 + 10;
	if (c >= 0x41 && c <= 0x46)
		return c - 0x41 + 10;
	return -1;
}

/* decodePairs: none for a single byte left or a pair not of digits. */
static bool model_pairs(const char *s, size_t len, __u8 *out)
{
	size_t i;

	for (i = 0; i < len; i += 2) {
		int hi, lo;

		if (i + 1 == len)
			return false;
		hi = model_nibble(s[i]);
		lo = model_nibble(s[i + 1]);
		if (hi < 0 || lo < 0)
			return false;
		out[i / 2] = (__u8)(hi * 16 + lo);
	}
	return true;
}

/* decode: the length check with size_mul(), then decodePairs. */
static bool model_decode(const char *s, size_t len, size_t n, __u8 *out)
{
	return len == model_size_mul(n, 2) && model_pairs(s, len, out);
}

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

static void encode_is_model(void)
{
	char out[2 * LEN_MAX + 1];
	size_t n, i;
	__u8 *in;

	__CPROVER_assume(n <= LEN_MAX);
	in = any_bytes(n);
	hex_encode(in, n, out);
	for (i = 0; i < n; i++)
		__CPROVER_assert(out[2 * i] == model_table[in[i] >> 4] &&
				 out[2 * i + 1] == model_table[in[i] & 0xf],
				 "encodeByte of each byte");
	__CPROVER_assert(!out[2 * n], "and the NUL");
}

static void decode_is_model(bool huge)
{
	__u8 out[LEN_MAX], want[LEN_MAX];
	size_t len, n, twice;
	bool model;
	char *s;
	int ret;

	__CPROVER_assume(len <= 2 * LEN_MAX + 1);
	__CPROVER_assume(huge ? check_mul_overflow(n, (size_t)2, &twice) :
			 n <= LEN_MAX);
	s = any_string(len);
	ret = hex_decode(s, out, n);
	model = model_decode(s, len, n, want);
	__CPROVER_assert(ret == (model ? 0 : -EINVAL), "decode's result");
	if (!ret)
		__CPROVER_assert(!memcmp(out, want, n), "and its bytes");
}

static void decode_max_is_model(bool huge)
{
	__u8 out[LEN_MAX + 1], want[LEN_MAX + 1];
	size_t len, cap, n, k, twice;
	bool model;
	char *s;
	int ret;

	__CPROVER_assume(len <= 2 * LEN_MAX + 1);
	__CPROVER_assume(huge ? check_mul_overflow(cap, (size_t)2, &twice) :
			 cap <= LEN_MAX);
	s = any_string(len);
	ret = hex_decode_max(s, out, cap, &n);
	k = min(len, model_size_add(model_size_mul(cap, 2), 1));
	model = !(k % 2) && model_decode(s, len, k / 2, want);
	__CPROVER_assert(ret == (model ? 0 : -EINVAL), "decodeMax's result");
	if (!ret)
		__CPROVER_assert(n == k / 2 && !memcmp(out, want, n),
				 "and its bytes");
}

void harness(void)
{
	encode_is_model();
	decode_is_model(false);
	decode_is_model(true);
	decode_max_is_model(false);
	decode_max_is_model(true);
}
