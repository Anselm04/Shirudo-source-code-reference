// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * log_records() of util/eventlog.c, which every eventlog reader runs on
 * what read_file() gives it, on every log of LEN bytes: it refuses one that
 * holds a NUL, and otherwise leaves the string of its whole lines, every
 * byte as it was, cutting only a last line without its newline.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/io.c"
#include "../../../util/eventlog.c"
#include "../../../util/string.c"

void harness(void)
{
	char *buf, *was;
	size_t i, n;

	buf = any_bytes(LEN + 1);
	buf[LEN] = '\0';
	was = any_bytes(LEN + 1);
	memcpy(was, buf, LEN + 1);
	if (log_records(buf, LEN)) {
		__CPROVER_assert(memchr(was, '\0', LEN),
				 "refuses only a log that holds a NUL");
		return;
	}
	n = strnlen(buf, LEN + 1);
	__CPROVER_assert(!memchr(was, '\0', LEN), "a log without a NUL");
	__CPROVER_assert(!n || buf[n - 1] == '\n', "whole lines");
	for (i = 0; i < n; i++)
		__CPROVER_assert(buf[i] == was[i], "kept as it was");
	for (i = n; i < LEN; i++)
		__CPROVER_assert(was[i] != '\n', "cutting only a torn line");
}
