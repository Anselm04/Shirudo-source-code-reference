// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_selectors_disjoint() and selector_covers() of
 * util/bpm_tree_overlap.c are disjoint and covers of
 * testing/proofs/lean4/Shirudo/TreeOverlap.lean on every two selectors of
 * up to LEN entries a list. bpm-tree-overlap-live.c includes this file for
 * tree_add_live().
 */

#include "proof.h"
#include "../../../util/kernel_release.c"
#include "../../../util/bpm_tree_overlap.c"
#include "bpm-tree-overlap-model.h"

#define TEXT_MAX	2

/* No harness here holds a selector against a node. */
static const char *model_kconfig(const char *key)
{
	return NULL;
}

/*
 * A selector is held in an operation: CBMC 5.95 reads wrong bytes at an
 * offset that depends on the data from an object that starts with an array
 * of char, as a selector on its own does. Only its two pointers are
 * written, as a write into its 12 KiB makes CBMC copy all of them.
 */
static void short_text(const char *s)
{
	__CPROVER_assume(!s[TEXT_MAX]);
}

static void short_list(const char (*list)[TREE_STRING_MAX], int n, int max)
{
	__CPROVER_assume(n >= 0 && n <= max);
	for (int i = 0; i < max; i++)
		short_text(list[i]);
}

static void short_pairs(const struct tree_selector_kv *kvs, int n, int max)
{
	__CPROVER_assume(n >= 0 && n <= max);
	for (int i = 0; i < max; i++) {
		short_text(kvs[i].key);
		short_list(kvs[i].values, kvs[i].n_values, max);
	}
}

#ifdef TREE_OVERLAP_LIVE
/* ends, of the operation at index and a later one. */
static bool model_ends(const struct tree_operation *add,
		       const struct tree_operation *later)
{
	return model_same(later->op, "delete") &&
	       model_same(later->id, add->id) &&
	       model_covers(&later->selector, &add->selector);
}

/*
 * The selectors name architectures alone, one or none, which is enough to
 * tell a delete that covers the add from one the add covers; the lists
 * left empty keep the loops over them out of the proof.
 */
static void add_live(void)
{
	struct tree_operation ops[OPS_MAX];
	struct tree_publication pub;

	pub.operations = ops;
	__CPROVER_assume(pub.n_operations >= 0 && pub.n_operations <= OPS_MAX);
	for (int i = 0; i < OPS_MAX; i++) {
		struct tree_selector *s = &ops[i].selector;

		/* "delete" and every other string of up to 7 bytes. */
		__CPROVER_assume(!ops[i].op[7]);
		short_text(ops[i].id);
		short_list(s->architecture, s->n_architecture, 1);
		s->n_kernel_release_prefix = 0;
		s->n_kernel_build_id = 0;
		s->n_kconfig = 0;
		s->n_labels = 0;
	}
	for (int index = 0; index < OPS_MAX; index++) {
		bool live = true;

		if (index >= pub.n_operations)
			break;
		for (int i = index + 1; i < OPS_MAX; i++)
			if (i < pub.n_operations)
				live &= !model_ends(&ops[index], &ops[i]);
		__CPROVER_assert(tree_add_live(&pub, index) == live,
				 "addLive of the model");
	}
}

void harness(void)
{
	add_live();
}
#else
/* A selector tree_parse() or the publisher could hold, and others. */
static void short_selector(struct tree_selector *s,
			   struct tree_selector_kv *kconfig,
			   struct tree_selector_kv *labels)
{
	s->kconfig = kconfig;
	s->labels = labels;
	short_list(s->kernel_release_prefix, s->n_kernel_release_prefix, LEN);
	short_list(s->kernel_build_id, s->n_kernel_build_id, LEN);
	short_list(s->architecture, s->n_architecture, LEN);
	short_pairs(kconfig, s->n_kconfig, LEN);
	short_pairs(labels, s->n_labels, LEN);
}

void harness(void)
{
	struct tree_selector_kv kconfig[2][LEN], labels[2][LEN];
	struct tree_operation ops[2];
	const struct tree_selector *a = &ops[0].selector;
	const struct tree_selector *b = &ops[1].selector;

	short_selector(&ops[0].selector, kconfig[0], labels[0]);
	short_selector(&ops[1].selector, kconfig[1], labels[1]);
	__CPROVER_assert(tree_selectors_disjoint(a, b) == model_disjoint(a, b),
			 "disjoint of the model");
	__CPROVER_assert(selector_covers(a, b) == model_covers(a, b),
			 "covers of the model");
}
#endif
