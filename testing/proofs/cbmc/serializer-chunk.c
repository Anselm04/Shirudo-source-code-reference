// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * serial_chunk_validate() of util/serializer.c for every chunk a map can
 * hold: one it accepts is the chunk asked for, of this invocation, and
 * names no more bytes than a chunk carries, so that a caller's copy of
 * bytes_in_chunk bytes stays inside it.
 */

#include <errno.h>

#include "proof.h"
#include "../../../util/serializer.c"

void harness(void)
{
	__u64 cursor, next_cursor, invocation_id;
	__u32 index, total, page;
	struct serial_chunk *c;
	int ret;

	__CPROVER_assert(serial_chunk_validate(NULL, index, total, page, cursor,
					       next_cursor, invocation_id) ==
			 -EINVAL, "no chunk");
	c = any_bytes(sizeof(*c));
	ret = serial_chunk_validate(c, index, total, page, cursor, next_cursor,
				    invocation_id);
	__CPROVER_assert(!ret || ret == -EINVAL || ret == -EBADMSG,
			 "0, -EINVAL or -EBADMSG");
	__CPROVER_assert((ret == -EINVAL) == !invocation_id,
			 "an invocation is never 0");
	__CPROVER_assert(!ret == (invocation_id &&
				  c->magic == SERIAL_MAGIC &&
				  c->version == SERIAL_VERSION &&
				  c->chunk_index == index &&
				  c->total_chunks == total &&
				  c->page_index == page &&
				  c->cursor == cursor &&
				  c->next_cursor == next_cursor &&
				  c->invocation_id == invocation_id &&
				  c->bytes_in_chunk <= SERIAL_CHUNK_PAYLOAD),
			 "exactly the chunk asked for, of this invocation");
	__CPROVER_assert(ret || c->bytes_in_chunk <= sizeof(c->data),
			 "its bytes lie inside the chunk");
}
