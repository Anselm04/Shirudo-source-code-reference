/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * testing/proofs/lean4/Shirudo/TreeOverlap.lean restated in C for the
 * harnesses that hold util/bpm_tree_overlap.c and tree_selector_matches()
 * to it. A function is named after the Lean definition it restates, and
 * the harness defines model_kconfig(), the node's kernel config.
 */

#ifndef SHIRUDO_PROOF_BPM_TREE_OVERLAP_MODEL_H
#define SHIRUDO_PROOF_BPM_TREE_OVERLAP_MODEL_H

/* Node; build_id is NULL for none. */
struct model_node {
	bool			uname;
	const char		*release;
	const char		*machine;
	const char		*build_id;
	const struct tree_kv	*labels;
	int			n_labels;
};

/* The value the node's kernel config gives a key, NULL for none. */
static const char *model_kconfig(const char *key);

/*
 * Equality of two strings, the bytes before their NULs. No read here is at
 * an index that depends on the strings: CBMC 5.95 reads wrong bytes at a
 * symbolic offset from an object of struct type.
 */
static bool model_same(const char *a, const char *b)
{
	for (size_t i = 0;; i++) {
		if (a[i] != b[i])
			return false;
		if (!a[i])
			return true;
	}
}

static bool model_list_holds(const char (*list)[TREE_STRING_MAX], int n,
			     const char *value)
{
	bool any = false;

	for (int i = 0; i < n; i++)
		any |= model_same(list[i], value);
	return any;
}

static bool model_lists_share(const char (*a)[TREE_STRING_MAX], int na,
			      const char (*b)[TREE_STRING_MAX], int nb)
{
	bool any = false;

	for (int i = 0; i < na; i++)
		any |= model_list_holds(b, nb, a[i]);
	return any;
}

static bool model_list_within(const char (*inner)[TREE_STRING_MAX],
			      int n_inner,
			      const char (*outer)[TREE_STRING_MAX],
			      int n_outer)
{
	bool all = true;

	for (int i = 0; i < n_inner; i++)
		all &= model_list_holds(outer, n_outer, inner[i]);
	return all;
}

/* continues, with boundary on what is left of the release. */
static bool model_continues(const char *release, const char *prefix)
{
	for (size_t i = 0;; i++) {
		if (!prefix[i])
			return !release[i] || release[i] == '.' ||
			       release[i] == '-';
		if (release[i] != prefix[i])
			return false;
	}
}

static bool model_prefix_matches(const char *release, const char *prefix)
{
	return !prefix[0] || model_continues(release, prefix);
}

static bool model_prefixes_share(const char (*a)[TREE_STRING_MAX], int na,
				 const char (*b)[TREE_STRING_MAX], int nb)
{
	bool any = false;

	for (int i = 0; i < na; i++)
		for (int j = 0; j < nb; j++)
			any |= model_prefix_matches(a[i], b[j]) ||
			       model_prefix_matches(b[j], a[i]);
	return any;
}

static bool model_prefixes_within(const char (*inner)[TREE_STRING_MAX],
				  int n_inner,
				  const char (*outer)[TREE_STRING_MAX],
				  int n_outer)
{
	bool all = true;

	for (int i = 0; i < n_inner; i++) {
		bool any = false;

		for (int j = 0; j < n_outer; j++)
			any |= model_prefix_matches(inner[i], outer[j]);
		all &= any;
	}
	return all;
}

static bool model_kvs_exclude(const struct tree_selector_kv *a, int na,
			      const struct tree_selector_kv *b, int nb)
{
	bool any = false;

	for (int i = 0; i < na; i++)
		for (int j = 0; j < nb; j++)
			any |= model_same(a[i].key, b[j].key) &&
			       !model_lists_share(a[i].values, a[i].n_values,
						  b[j].values, b[j].n_values);
	return any;
}

static bool model_kvs_within(const struct tree_selector_kv *inner, int n_inner,
			     const struct tree_selector_kv *outer, int n_outer)
{
	bool all = true;

	for (int j = 0; j < n_outer; j++) {
		bool any = false;

		for (int i = 0; i < n_inner; i++)
			any |= model_same(inner[i].key, outer[j].key) &&
			       model_list_within(inner[i].values,
						 inner[i].n_values,
						 outer[j].values,
						 outer[j].n_values);
		all &= any;
	}
	return all;
}

static bool model_disjoint(const struct tree_selector *a,
			   const struct tree_selector *b)
{
	return (a->n_architecture && b->n_architecture &&
		!model_lists_share(a->architecture, a->n_architecture,
				   b->architecture, b->n_architecture)) ||
	       (a->n_kernel_build_id && b->n_kernel_build_id &&
		!model_lists_share(a->kernel_build_id, a->n_kernel_build_id,
				   b->kernel_build_id, b->n_kernel_build_id)) ||
	       (a->n_kernel_release_prefix && b->n_kernel_release_prefix &&
		!model_prefixes_share(a->kernel_release_prefix,
				      a->n_kernel_release_prefix,
				      b->kernel_release_prefix,
				      b->n_kernel_release_prefix)) ||
	       model_kvs_exclude(a->kconfig, a->n_kconfig, b->kconfig,
				 b->n_kconfig) ||
	       model_kvs_exclude(a->labels, a->n_labels, b->labels,
				 b->n_labels);
}

static bool model_covers(const struct tree_selector *outer,
			 const struct tree_selector *inner)
{
	return (!outer->n_architecture ||
		(inner->n_architecture &&
		 model_list_within(inner->architecture, inner->n_architecture,
				   outer->architecture,
				   outer->n_architecture))) &&
	       (!outer->n_kernel_build_id ||
		(inner->n_kernel_build_id &&
		 model_list_within(inner->kernel_build_id,
				   inner->n_kernel_build_id,
				   outer->kernel_build_id,
				   outer->n_kernel_build_id))) &&
	       (!outer->n_kernel_release_prefix ||
		(inner->n_kernel_release_prefix &&
		 model_prefixes_within(inner->kernel_release_prefix,
				       inner->n_kernel_release_prefix,
				       outer->kernel_release_prefix,
				       outer->n_kernel_release_prefix))) &&
	       model_kvs_within(inner->kconfig, inner->n_kconfig,
				outer->kconfig, outer->n_kconfig) &&
	       model_kvs_within(inner->labels, inner->n_labels, outer->labels,
				outer->n_labels);
}

static const char *model_kv_value(const struct tree_kv *labels, int n,
				  const char *key)
{
	for (int i = 0; i < n; i++)
		if (model_same(labels[i].key, key))
			return labels[i].value;
	return NULL;
}

/* pairHeld of every pair, on the value the node has or NULL. */
static bool model_pair_held(const struct tree_selector_kv *pair,
			    const char *value)
{
	return value && model_list_holds(pair->values, pair->n_values, value);
}

static bool model_wildcard(const struct tree_selector *s)
{
	return !s->n_kernel_release_prefix && !s->n_kernel_build_id &&
	       !s->n_architecture && !s->n_kconfig && !s->n_labels;
}

static bool model_matches_on(const struct model_node *n,
			     const struct tree_selector *s)
{
	bool release = false, kconfig = true, labels = true;

	for (int i = 0; i < s->n_kernel_release_prefix; i++)
		release |= model_prefix_matches(n->release,
						s->kernel_release_prefix[i]);
	for (int i = 0; i < s->n_kconfig; i++)
		kconfig &= model_pair_held(&s->kconfig[i],
					   model_kconfig(s->kconfig[i].key));
	for (int i = 0; i < s->n_labels; i++)
		labels &= model_pair_held(&s->labels[i],
					  model_kv_value(n->labels, n->n_labels,
							 s->labels[i].key));
	return (!s->n_kernel_release_prefix || release) &&
	       (!s->n_kernel_build_id ||
		(n->build_id &&
		 model_list_holds(s->kernel_build_id, s->n_kernel_build_id,
				  n->build_id))) &&
	       (!s->n_architecture ||
		model_list_holds(s->architecture, s->n_architecture,
				 n->machine)) &&
	       kconfig && labels;
}

static bool model_selector_matches(const struct model_node *n,
				   const struct tree_selector *s)
{
	return model_wildcard(s) || (n->uname && model_matches_on(n, s));
}

#endif /* SHIRUDO_PROOF_BPM_TREE_OVERLAP_MODEL_H */
