// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_operations_reserve() of util/bpm_tree.c, which grows the operations
 * tree_parse() reads from a registry, from every count and capacity: the
 * array kept while it has room, a full one grown to 16 operations or twice
 * its size and never past TREE_MAX_OPS, and a refusal at TREE_MAX_OPS or
 * a failed allocation that changes nothing. The allocator is its contract:
 * an array of operations of 13 KiB each is past what CBMC can copy.
 */

#include "proof.h"

#define xreallocarray	reserve_realloc
#include "../../../util/bpm_tree.c"
#undef xreallocarray

static char before, after;
static bool alloc_fails;
static int calls;
static void *got;
static size_t got_old, got_new, got_size;

void *reserve_realloc(void *ptr, size_t old_nmemb, size_t new_nmemb,
		      size_t size)
{
	calls++;
	got = ptr;
	got_old = old_nmemb;
	got_new = new_nmemb;
	got_size = size;
	return alloc_fails ? NULL : &after;
}

void harness(void)
{
	struct tree_publication pub = {};
	int n, cap, want, ret;
	bool fails, kept;
	void *was;

	__CPROVER_assume(cap >= 0 && cap <= TREE_MAX_OPS && n >= 0 && n <= cap);
	alloc_fails = fails;
	was = cap ? &before : NULL;
	pub.n_operations = n;
	pub.operations_capacity = cap;
	pub.operations = was;
	ret = tree_operations_reserve(&pub);
	kept = pub.operations == was && pub.operations_capacity == cap &&
	       pub.n_operations == n;
	if (n >= TREE_MAX_OPS) {
		__CPROVER_assert(ret == -E2BIG && !calls && kept,
				 "no operation past TREE_MAX_OPS");
		return;
	}
	if (n < cap) {
		__CPROVER_assert(!ret && !calls && kept,
				 "an array with room kept as it is");
		return;
	}
	want = cap ? min(2 * cap, TREE_MAX_OPS) : 16;
	__CPROVER_assert(calls == 1 && got == was && got_old == (size_t)cap &&
			 got_new == (size_t)want &&
			 got_size == sizeof(struct tree_operation),
			 "a full array grown to 16 or twice, at most TREE_MAX_OPS");
	if (fails) {
		__CPROVER_assert(ret == -ENOMEM && kept,
				 "a failed allocation changes nothing");
		return;
	}
	__CPROVER_assert(!ret && pub.operations == (void *)&after &&
			 pub.operations_capacity == want && n < want &&
			 pub.n_operations == n, "room for one more operation");
}
