// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_buffer_append() of util/bpm_oci.c, which keeps every registry body
 * read into memory, from a buffer of LEN bytes holding any body shorter,
 * for every chunk of up to CHUNK_MAX bytes and an allocation that may
 * fail: refused exactly when the body would reach BPM_MAX_HTTP_BODY, and
 * then or without memory nothing changed; else the chunk behind the body,
 * inside the buffer and terminated. The limit is 16 bytes here for its
 * 16 MiB: the checks against it are the same expressions.
 */

#define BPM_MAX_HTTP_BODY	16u
#define CHUNK_MAX		8

/* util/malloc.c behind a file that includes its header. */
#define MALLOC_INTERNAL
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_oci.c"
#include "../../../util/malloc.c"

void harness(void)
{
	struct bpm_buffer b = { .cap = LEN };
	char was[LEN ? LEN : 1], *chunk;
	size_t len, n, i;
	__u8 *data;
	int ret;

	__CPROVER_assume(n <= CHUNK_MAX &&
			 (LEN ? len < LEN && len < BPM_MAX_HTTP_BODY : !len));
	data = LEN ? any_bytes(LEN) : NULL;
	for (i = 0; i < LEN; i++)
		was[i] = data[i];
	b.data = data;
	b.len = len;
	chunk = any_bytes(CHUNK_MAX);
	ret = bpm_buffer_append(&b, chunk, n);
	if (n >= BPM_MAX_HTTP_BODY - len || ret == -ENOMEM) {
		__CPROVER_assert(ret == (n >= BPM_MAX_HTTP_BODY - len ? -E2BIG :
					 -ENOMEM) &&
				 b.data == data && b.len == len && b.cap == LEN,
				 "refused at the limit or without memory, nothing "
				 "changed");
		return;
	}
	__CPROVER_assert(!ret && b.len == len + n && b.len < b.cap &&
			 !b.data[b.len], "the body grown, inside and terminated");
	__CPROVER_assert(len + n + 1 <= LEN ? b.data == data && b.cap == LEN :
			 b.cap > len + n, "a buffer with room kept");
	for (i = 0; i < BPM_MAX_HTTP_BODY; i++) {
		if (i < len)
			__CPROVER_assert(b.data[i] == (__u8)was[i],
					 "the body kept");
		else if (i < len + n)
			__CPROVER_assert(b.data[i] == (__u8)chunk[i - len],
					 "the chunk behind it");
	}
}
