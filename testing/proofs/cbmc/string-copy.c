// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * strscpy() of util/string.c for every string and buffer of up to
 * LEN_MAX bytes: it terminates what it writes and copies the whole
 * string or says that it cut it.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define LEN_MAX	8

static void copied_string(void)
{
	size_t size, n;
	char *dst, *src;
	ssize_t ret;

	__CPROVER_assume(size <= LEN_MAX && n <= LEN_MAX);
	src = any_bytes(n + 1);
	__CPROVER_assume(!src[n] && strnlen(src, n) == n);
	dst = any_bytes(size);
	ret = strscpy(dst, src, size);
	if (size < 1) {
		__CPROVER_assert(ret == -E2BIG, "no room is -E2BIG");
		return;
	}
	__CPROVER_assert(memchr(dst, 0, size), "terminated");
	if (n < size)
		__CPROVER_assert(ret == (ssize_t)n && !memcmp(dst, src, n + 1),
				 "the whole string and its length");
	else
		__CPROVER_assert(ret == -E2BIG && !memcmp(dst, src, size - 1) &&
				 !dst[size - 1], "what fits, and -E2BIG");
}

void harness(void)
{
	copied_string();
}
