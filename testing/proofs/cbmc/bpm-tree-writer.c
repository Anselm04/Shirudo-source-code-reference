// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_emit_publication() of util/bpm_tree.c, which bpm tree append signs,
 * against tree_parse(), on publications without operations that LEN
 * picks: tree, generation, parent, base and head read back as written, up
 * to the last generation and sequence number the target takes.
 */

/* util/string.c behind a file that includes its header. */
#define STRING_INTERNAL

#include <stdint.h>
#include <stdlib.h>

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/bpm_tree.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

#define DOC_MAX		512
#define PARENT								\
	"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

enum { FIRST, LAST, GENERATION_PAST, HEAD_PAST, UNNAMED };

/*
 * The allocator hands out objects of their types, so that the bytes
 * written are the bytes read back: the document in DOC_MAX bytes of the
 * 4 KiB asked for, and the reader's state.
 */
void *xmalloc(size_t size)
{
	static char document[DOC_MAX];

	return document;
}

void *xcalloc(size_t nmemb, size_t size)
{
	static struct tree_reader reader;

	__CPROVER_assert(nmemb == 1 && size == sizeof(reader),
			 "only tree_parse() allocates so");
	return &reader;
}

void xfree(void *p, size_t size)
{
}

void harness(void)
{
	static const struct tree_publication cases[] = {
		[FIRST] = { .schema = 1, .tree_id = "tree", .generation = 1 },
		[LAST] = {
			.schema = 1, .tree_id = "tree",
			.generation = INT64_MAX - 1,
			.parent_manifest_digest = PARENT,
			.head_seq = INT64_MAX - 1,
		},
		[GENERATION_PAST] = {
			.schema = 1, .tree_id = "tree", .generation = INT64_MAX,
		},
		[HEAD_PAST] = {
			.schema = 1, .tree_id = "tree", .generation = 1,
			.head_seq = INT64_MAX,
		},
		[UNNAMED] = { .schema = 1, .generation = 1 },
	};
	const struct tree_publication *pub = &cases[LEN];
	struct tree_publication back;
	const int written = LEN;
	size_t len = 0;
	char *body;
	int ret;

	__CPROVER_assert(!tree_emit_publication(pub, NULL, &body, &len),
			 "a publication written");
	ret = tree_parse(body, len, &back);
	/* bpm tree append refuses to write the last three. */
	__CPROVER_assert(ret == (written <= LAST ? 0 : -EINVAL),
			 "read up to the last generation and sequence number");
	if (ret)
		return;
	__CPROVER_assert(back.schema == 1 && !strcmp(back.tree_id, pub->tree_id) &&
			 back.generation == pub->generation &&
			 !strcmp(back.parent_manifest_digest,
				 pub->parent_manifest_digest) &&
			 back.base_seq == pub->base_seq &&
			 back.head_seq == pub->head_seq && !back.n_operations,
			 "tree, generation, parent, base and head as written");
	__CPROVER_assert(tree_publication_check(&back) ==
			 (written == FIRST ? 0 : -EINVAL),
			 "tree sync goes on with one whose head is its base");
}
