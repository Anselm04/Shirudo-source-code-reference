// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A serializer page as map export reassembles it from the chunks of the
 * output map, here read from the input, 4096 bytes a chunk.
 */

#include <errno.h>

#include "fuzz.h"

static const __u8 *chunks;
static size_t chunks_len;

/* <bpf/bpf.h> declares it under the name it replaces. */
#define bpf_map_lookup_elem fuzz_lookup
#include "upatch_maps.c"

int fuzz_lookup(int fd, const void *key, void *value)
{
	size_t off = (size_t)*(const __u32 *)key *
		     sizeof(struct serial_chunk);
	size_t n;

	if (off >= chunks_len) {
		errno = ENOENT;
		return -1;
	}
	n = chunks_len - off;
	if (n > sizeof(struct serial_chunk))
		n = sizeof(struct serial_chunk);
	memset(value, 0, sizeof(struct serial_chunk));
	memcpy(value, chunks + off, n);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct bpf_map_info info = { .max_entries = 64 };
	struct serial_chunk first = {};
	struct serial_page page;

	chunks = data;
	chunks_len = size;
	/* The page the reader asks for is the one a consistent serializer wrote. */
	memcpy(&first, data, min(size, sizeof(first)));
	if (!read_serial_page(0, &info, first.page_index, first.cursor,
			      first.invocation_id, &page))
		xfree(page.data, page.bytes);
	return 0;
}
