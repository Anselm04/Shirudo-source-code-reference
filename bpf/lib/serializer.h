/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * ABI for upatch-local map serializers. Serializer programs are
 * SEC("syscall") BPF programs named shirudo_serialize__<map_name>.
 */

#ifndef SHIRUDO_SERIALIZER_H
#define SHIRUDO_SERIALIZER_H

#include "misc.h"

#define SERIAL_MAP_NAME		"shirudo_ser"
#define SERIAL_MAGIC		0x5a4c5253u	/* "SRLZ" le */
#define SERIAL_VERSION		1u
#define SERIAL_MAP_NAME_MAX	16u
#define SERIAL_MAX_CHUNKS	256u
#define SERIAL_MAX_PAGES	256u
#define SERIAL_F_DONE		(1u << 0)

/* ctx->flags: read the live state without draining it. */
#define SERIAL_CTX_F_PEEK	(1u << 0)

/*
 * Keep the syscall test-run context within the older five-u64 argument
 * limit. Page result metadata lives in struct serial_chunk.
 */
#define SERIAL_CTX_MAX_BYTES	40u

/*
 * Keep the chunk value at exactly 4096 bytes: a 64-byte header plus
 * payload. This is friendly to map value allocation and easy to inspect.
 */
#define SERIAL_CHUNK_PAYLOAD	4032u

struct serialize_ctx {
	__u32		magic;
	__u32		version;
	__u32		flags;
	__u32		max_chunks;
	__u32		chunk_payload_size;
	__u32		page_index;
	__u64		cursor;
	__u64		invocation_id;
};

struct serial_chunk {
	__u32		magic;
	__u32		version;
	__u32		flags;
	int		status;
	__u32		chunk_index;
	__u32		total_chunks;
	__u32		bytes_total;
	__u32		bytes_in_chunk;
	__u32		page_index;
	__u32		reserved;
	__u64		cursor;
	__u64		next_cursor;
	__u64		invocation_id;
	__u8		data[SERIAL_CHUNK_PAYLOAD];
};

BUILD_BUG_ON(sizeof(struct serialize_ctx) !=
	     SERIAL_CTX_MAX_BYTES);
BUILD_BUG_ON(sizeof(struct serial_chunk) != 4096);

#endif /* SHIRUDO_SERIALIZER_H */
