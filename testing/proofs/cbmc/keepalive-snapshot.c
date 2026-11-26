// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * keepalive_snapshot() of util/keepalive.c, which reads the tree keys a
 * keepalive reports without the tree lock, for every answer of its reads:
 * a try is over when its two reads of the state agree, the state handed
 * back is the first read of the last try, PENDING says that try saw
 * pending.json and UNSETTLED that the tries ran out; collect()'s error is
 * returned at once with no flag set.
 */

#include "proof.h"
#include "../../../util/keepalive.c"

#define READS	(2 * KEEPALIVE_SNAPSHOT_TRIES)

/* What each call of a kind answers, in the order they come. */
struct answers {
	int		rc[READS];
	int		schema[READS];
	__s64		generation[READS], last_seq[READS];
	__s64		head_seq[READS], base_seq[READS];
	char		tree_id[READS], root[READS], root_tpm[READS];
	char		manifest[READS];
	bool		pending[READS];
	int		collect[KEEPALIVE_SNAPSHOT_TRIES];
	int		reads, pendings, collects;
};

static struct answers *in;

/* A state of any fields, its strings of one byte. */
static void fill(struct tree_state *s, int k)
{
	*s = (struct tree_state){
		.schema = in->schema[k], .generation = in->generation[k],
		.last_seq = in->last_seq[k], .head_seq = in->head_seq[k],
		.segment_base_seq = in->base_seq[k],
	};
	s->tree_id[0] = in->tree_id[k];
	s->projection_root[0] = in->root[k];
	s->projection_root_tpm[0] = in->root_tpm[k];
	s->manifest_digest[0] = in->manifest[k];
}

static int read_state(void *ctx, struct tree_state *state)
{
	int k = in->reads++;

	__CPROVER_assert(k < READS, "two reads a try");
	fill(state, k);
	return in->rc[k];
}

static bool pending(void *ctx)
{
	int k = in->pendings++;

	__CPROVER_assert(k < READS, "two looks a try");
	return in->pending[k];
}

static int collect(void *ctx, const struct tree_state *state, int state_rc)
{
	int k = in->collects++;

	__CPROVER_assert(k < KEEPALIVE_SNAPSHOT_TRIES, "one collect a try");
	__CPROVER_assert(state_rc == in->rc[2 * k] &&
			 state->schema == in->schema[2 * k] &&
			 state->last_seq == in->last_seq[2 * k],
			 "the first read of its try collected");
	return in->collect[k];
}

static const struct keepalive_snapshot_ops ops = {
	read_state, pending, collect,
};

/* The two reads of try t agree: the same error, or the same state. */
static bool agree(int t)
{
	int a = 2 * t, b = 2 * t + 1;

	if (in->rc[a] || in->rc[b])
		return in->rc[a] == in->rc[b];
	return in->schema[a] == in->schema[b] &&
	       in->generation[a] == in->generation[b] &&
	       in->last_seq[a] == in->last_seq[b] &&
	       in->head_seq[a] == in->head_seq[b] &&
	       in->base_seq[a] == in->base_seq[b] &&
	       in->tree_id[a] == in->tree_id[b] && in->root[a] == in->root[b] &&
	       in->root_tpm[a] == in->root_tpm[b] &&
	       in->manifest[a] == in->manifest[b];
}

void harness(void)
{
	struct answers any;
	struct tree_state state;
	__u32 flags, was;
	int ret, state_rc, t, last;
	bool settled = false;

	in = &any;
	in->reads = 0;
	in->pendings = 0;
	in->collects = 0;
	was = flags;
	ret = keepalive_snapshot(&ops, NULL, &state, &state_rc, &flags);
	for (t = 0; t < KEEPALIVE_SNAPSHOT_TRIES; t++) {
		if (in->collect[t]) {
			__CPROVER_assert(ret == in->collect[t] &&
					 in->collects == t + 1 && flags == was,
					 "collect()'s error at once, no flag set");
			return;
		}
		last = t;
		settled = agree(t);
		if (settled)
			break;
	}
	__CPROVER_assert(!ret && in->collects == last + 1 &&
			 in->reads == 2 * last + 2,
			 "tries up to the first whose reads agree");
	__CPROVER_assert(state_rc == in->rc[2 * last] &&
			 state.schema == in->schema[2 * last] &&
			 state.last_seq == in->last_seq[2 * last] &&
			 state.tree_id[0] == in->tree_id[2 * last],
			 "the first read of the last try");
	__CPROVER_assert(!!(flags & KEEPALIVE_TREE_OP_PENDING) ==
			 (in->pending[2 * last] || in->pending[2 * last + 1] ||
			  !!(was & KEEPALIVE_TREE_OP_PENDING)),
			 "PENDING when the last try saw pending.json");
	__CPROVER_assert(!!(flags & KEEPALIVE_SNAPSHOT_UNSETTLED) ==
			 (!settled || !!(was & KEEPALIVE_SNAPSHOT_UNSETTLED)),
			 "UNSETTLED exactly when no try's reads agreed");
	__CPROVER_assert(!(flags & ~was & ~(KEEPALIVE_TREE_OP_PENDING |
					    KEEPALIVE_SNAPSHOT_UNSETTLED)),
			 "no other flag set");
}
