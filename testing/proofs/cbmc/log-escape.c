// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * escape() of util/log.c, which every message passes before syslog and the
 * terminal, on every message of up to LEN bytes and every buffer: it writes
 * a terminated line of printable ASCII inside the buffer that decodes back
 * to the message, or to a start of it cut between two characters.
 */

#include "proof.h"
#include "../../../util/log.c"

static bool octal(char c)
{
	return c >= '0' && c <= '7';
}

void harness(void)
{
	size_t cap, len, i, n, k;
	char *src, *dst;
	__u8 c;

	src = any_bytes(LEN + 1);
	src[LEN] = '\0';
	len = strnlen(src, LEN);
	__CPROVER_assume(cap >= 1 && cap <= 4 * LEN + 2);
	dst = any_bytes(cap);
	escape(dst, cap, src);
	for (i = 0, n = 0; dst[i]; n++) {
		__CPROVER_assert(i + 1 < cap, "terminated inside the buffer");
		__CPROVER_assert(dst[i] >= 0x20 && dst[i] < 0x7f,
				 "printable ASCII only");
		if (dst[i] != '\\') {
			c = dst[i++];
		} else if (dst[i + 1] == '\\') {
			c = '\\';
			i += 2;
		} else {
			__CPROVER_assert(dst[i + 1] <= '3' && octal(dst[i + 1]) &&
					 octal(dst[i + 2]) && octal(dst[i + 3]),
					 "a backslash, then itself or 3 octal digits");
			c = (dst[i + 1] - '0') << 6 | (dst[i + 2] - '0') << 3 |
			    (dst[i + 3] - '0');
			i += 4;
		}
		__CPROVER_assert(n < len && c == (__u8)src[n],
				 "decodes to the message");
	}
	k = 4 * len + 1;
	if (cap >= k)
		__CPROVER_assert(n == len, "the whole message when it fits");
}
