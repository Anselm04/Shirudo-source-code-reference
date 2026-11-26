// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * lines_len() of util/io.c, which the eventlog and tree log readers trust
 * to drop a torn last record, for every buffer of up to LEN_MAX bytes: it
 * ends at a newline or is 0, and leaves no newline behind it.
 */

#include "proof.h"
#include "../../../util/io.c"

#define LEN_MAX	8

void harness(void)
{
	size_t len, n, i;
	char *buf;

	__CPROVER_assume(len <= LEN_MAX);
	buf = any_bytes(len);
	n = lines_len(buf, len);
	__CPROVER_assert(n <= len, "within the buffer");
	__CPROVER_assert(!n || buf[n - 1] == '\n', "ends at a newline");
	for (i = n; i < len; i++)
		__CPROVER_assert(buf[i] != '\n', "no newline after it");
}
