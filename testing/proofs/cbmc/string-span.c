// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * span_to_str() of util/string.c for every span and buffer of up to
 * LEN_MAX bytes, apart or the span in the buffer: the bytes are a string
 * exactly when none of them is a NUL and they fit with a terminator, the
 * string is then the bytes and ends behind them, and a refusal writes
 * nothing. The span is allocated at its length, so a read past it fails.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define LEN_MAX	6

static bool holds_nul(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (!s[i])
			return true;
	return false;
}

static void check(const char *dst, const char *was, size_t cap,
		  const char *src, size_t len, int ret)
{
	size_t i;

	if (holds_nul(src, len)) {
		__CPROVER_assert(ret == -EINVAL, "a NUL among the bytes refused");
	} else if (len >= cap) {
		__CPROVER_assert(ret == -E2BIG, "no room for the terminator");
	} else {
		__CPROVER_assert(!ret, "bytes without a NUL that fit taken");
		__CPROVER_assert(!dst[len], "terminated behind the bytes");
		for (i = 0; i < len; i++)
			__CPROVER_assert(dst[i] == src[i] && dst[i],
					 "the string is the bytes");
	}
	for (i = ret ? 0 : len + 1; i < cap; i++)
		__CPROVER_assert(dst[i] == was[i],
				 "nothing else written, nothing at all on a refusal");
}

static void span_apart(void)
{
	char was[LEN_MAX + 1];
	char *dst, *src;
	size_t cap, len;
	int ret;

	__CPROVER_assume(cap <= LEN_MAX + 1 && len <= LEN_MAX);
	src = any_bytes(len);
	dst = any_bytes(cap);
	memcpy(was, dst, cap);
	ret = span_to_str(dst, cap, src, len);
	check(dst, was, cap, src, len, ret);
}

static void span_in_place(void)
{
	char was[LEN_MAX + 1];
	size_t cap, len;
	char *buf;
	int ret;

	__CPROVER_assume(cap <= LEN_MAX + 1 && len <= cap);
	buf = any_bytes(cap);
	memcpy(was, buf, cap);
	ret = span_to_str(buf, cap, buf, len);
	check(buf, was, cap, was, len, ret);
}

void harness(void)
{
	span_apart();
	span_in_place();
}
