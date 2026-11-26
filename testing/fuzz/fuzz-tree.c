// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_parse() on an upatch tree publication, the canonical
 * digest of every operation it accepts and the publication emitted again,
 * bare and with the publisher's fixes, which must read back with the same
 * base, operations and digests and pass tree_publication_check() exactly
 * when the first did. A segment the check passes names its predecessor
 * when it starts past 0, and never precedes itself. tree_publication_verify()
 * passes only what the check passes and names the operation that failed.
 */

#include <stdlib.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "bpm_tree.h"
#include "json.h"
#include "malloc.h"

static int emit_fixes(struct json_emit *e, int index, void *ctx)
{
	if (index % 2)
		return 0;
	json_arr_open(e, "fixes");
	json_str(e, "EXAMPLE-0101");
	json_str(e, ((const struct tree_publication *)ctx)->tree_id);
	json_arr_close(e);
	return 0;
}

static void read_back(const struct tree_publication *pub,
		      const struct tree_emit_extra *extra)
{
	char digest[72], back[72], *out;
	struct tree_publication again;
	size_t len;

	if (tree_emit_publication(pub, extra, &out, &len))
		return;
	if (tree_parse(out, len, &again) ||
	    again.n_operations != pub->n_operations ||
	    strcmp(again.tree_id, pub->tree_id) ||
	    again.generation != pub->generation ||
	    again.base_seq != pub->base_seq ||
	    strcmp(again.segment_manifest_digest,
		   pub->segment_manifest_digest) ||
	    strcmp(again.history_root, pub->history_root) ||
	    again.head_seq != pub->head_seq ||
	    !tree_publication_check(&again) != !tree_publication_check(pub))
		abort();
	for (int i = 0; i < pub->n_operations; i++) {
		if (tree_operation_digest(&pub->operations[i], digest) !=
		    tree_operation_digest(&again.operations[i], back) ||
		    strcmp(digest, back) ||
		    strcmp(again.operations[i].operation_digest,
			   pub->operations[i].operation_digest))
			abort();
	}
	tree_publication_free(&again);
	xfree(out, len);
}

static void verify_names_its_failure(const struct tree_publication *pub)
{
	int bad_op, ret;

	ret = tree_publication_verify(pub, &bad_op);
	if (bad_op < -1 || bad_op >= pub->n_operations ||
	    (!ret && (bad_op != -1 || tree_publication_check(pub))) ||
	    (bad_op >= 0 &&
	     tree_operation_validate(&pub->operations[bad_op]) != ret))
		abort();
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct tree_publication pub;
	struct tree_emit_extra extra = { emit_fixes, &pub };

	if (tree_parse((const char *)data, size, &pub))
		return 0;
	if (!tree_publication_check(&pub) &&
	    (!pub.segment_manifest_digest[0] != !pub.base_seq ||
	     !pub.history_root[0] != !pub.base_seq ||
	     (pub.base_seq && !pub.n_operations) ||
	     !tree_segment_precedes(&pub, pub.segment_manifest_digest, &pub)))
		abort();
	verify_names_its_failure(&pub);
	read_back(&pub, NULL);
	read_back(&pub, &extra);
	tree_publication_free(&pub);
	return 0;
}
