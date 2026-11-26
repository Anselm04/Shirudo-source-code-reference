// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_publication_follows() of util/bpm_tree.c, which decides whether
 * bpm tree sync may apply a signed publication over the state the node
 * recorded, for every sequence number and generation a __s64 holds: it
 * accepts exactly a publication of the same tree, of a later generation
 * unless it is the same manifest, naming the recorded parent when it is
 * the next generation, with its head not before the node's cursor, and
 * asks for a walk back exactly when such a publication starts past the
 * cursor, or past 0 without a state. And tree_segment_precedes(), one
 * step of that walk, which accepts exactly the segment the successor
 * names, of its tree, ending at its base and of a lower generation. And
 * tree_walk_within(), the limit of that walk, which allows exactly
 * TREE_MAX_JOIN_OPS operations back from 0 and TREE_MAX_WALK_OPS from any
 * other cursor. Strings are of up to two bytes.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/hex.c"
#include "../../../util/bpm_tree.c"

static void short_string(const char *s)
{
	__CPROVER_assume(s[2] == '\0');
}

static void follows_the_state(void)
{
	struct tree_publication pub;
	struct tree_state state;
	char manifest[3];
	bool have, same, next, refused;
	int ret;

	short_string(pub.tree_id);
	short_string(pub.parent_manifest_digest);
	short_string(state.tree_id);
	short_string(state.manifest_digest);
	short_string(manifest);
	ret = tree_publication_follows(&pub, have ? &state : NULL, manifest);
	if (!have) {
		__CPROVER_assert(ret == (pub.base_seq ? TREE_FOLLOWS_WALK : 0),
				 "without a state, a walk unless it starts at 0");
		return;
	}
	same = !strcmp(state.manifest_digest, manifest);
	next = pub.generation > state.generation &&
	       pub.generation - 1 == state.generation;
	refused = strcmp(pub.tree_id, state.tree_id) ||
		  (!same && pub.generation <= state.generation) ||
		  (!same && next && pub.parent_manifest_digest[0] &&
		   strcmp(pub.parent_manifest_digest, state.manifest_digest)) ||
		  pub.head_seq < state.last_seq;
	__CPROVER_assert(ret == 0 || ret == TREE_FOLLOWS_WALK ||
			 ret == -EINVAL || ret == -ERANGE,
			 "0, a walk or a refusal");
	__CPROVER_assert((ret < 0) == refused,
			 "refused exactly for another tree, an older generation, "
			 "another parent or a head before the cursor");
	__CPROVER_assert(ret < 0 ||
			 (ret == TREE_FOLLOWS_WALK) ==
			 (pub.base_seq > state.last_seq),
			 "a walk exactly when it starts past the cursor");
}

static void precedes_the_successor(void)
{
	struct tree_publication pred, succ;
	char digest[3];
	bool named;
	int ret;

	short_string(pred.tree_id);
	short_string(succ.tree_id);
	short_string(succ.segment_manifest_digest);
	short_string(digest);
	ret = tree_segment_precedes(&pred, digest, &succ);
	named = succ.base_seq > 0 &&
		!strcmp(succ.segment_manifest_digest, digest) &&
		!strcmp(pred.tree_id, succ.tree_id) &&
		pred.head_seq == succ.base_seq &&
		pred.generation < succ.generation;
	__CPROVER_assert(ret == 0 || ret == -ERANGE, "0 or -ERANGE");
	__CPROVER_assert(!ret == named,
			 "exactly the earlier segment of the tree that the "
			 "successor names, ending at its base");
}

static void walks_within_the_limit(void)
{
	__s64 base, last;
	int ret = tree_walk_within(base, last);

	__CPROVER_assert(ret == 0 || ret == -E2BIG || ret == -EINVAL,
			 "0, -E2BIG or -EINVAL");
	__CPROVER_assert((ret == -EINVAL) == (base < 0 || last < 0),
			 "-EINVAL exactly for a negative number");
	__CPROVER_assert(ret == -EINVAL || !ret ==
			 (base <= last ||
			  (last ? base - last <= TREE_MAX_WALK_OPS :
				  base <= TREE_MAX_JOIN_OPS)),
			 "within the walk limit of a running node, or of one "
			 "at 0 that joins");
}

void harness(void)
{
	follows_the_state();
	precedes_the_successor();
	walks_within_the_limit();
}
