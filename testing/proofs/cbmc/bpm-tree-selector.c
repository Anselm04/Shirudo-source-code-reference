// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The selector pairs of util/bpm_tree.c, which a tree publication fills
 * from a registry, LEN of them: a pair is added only below its limit, as a
 * new zeroed one after those it keeps, a copy owns its pairs and a freed
 * selector holds none, and a tree string has no control byte.
 */

/* util/malloc.c and util/string.c behind a file that includes their headers. */
#define MALLOC_INTERNAL
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_tree.c"
#include "../../../util/malloc.c"
#include "../../../util/string.c"

#define KEY_MAX		3
#define TEXT_MAX	8

static void text(void)
{
	char *s = any_bytes(TEXT_MAX + 1);
	bool control = false;
	size_t i;

	__CPROVER_assume(!s[TEXT_MAX]);
	for (i = 0; s[i]; i++)
		control |= (__u8)s[i] < 0x20;
	__CPROVER_assert(tree_text(s) == !control,
			 "a tree string has no control byte");
}

static struct tree_selector_kv *pairs(int n)
{
	struct tree_selector_kv *kvs;
	int i;

	if (!n)
		return NULL;
	kvs = __CPROVER_allocate((size_t)n * sizeof(*kvs), 0);
	__CPROVER_assume(kvs);
	for (i = 0; i < n; i++)
		__CPROVER_assume(!kvs[i].key[KEY_MAX]);
	return kvs;
}

/* A byte of every part of a pair, at any place. */
struct probe {
	size_t	i, j;
};

static struct probe any_probe(void)
{
	struct probe p;

	__CPROVER_assume(p.i < TREE_STRING_MAX &&
			 p.j < TREE_MAX_SELECTOR_VALUES);
	return p;
}

/* The probed bytes of a pair, to hold against another. */
struct sample {
	char	key, value;
	int	n_values;
};

static struct sample sample(const struct tree_selector_kv *kv,
			    struct probe p)
{
	struct sample s = {
		kv->key[p.i], kv->values[p.j][p.i], kv->n_values,
	};

	return s;
}

static bool same(const struct tree_selector_kv *kv, struct sample s,
		 struct probe p)
{
	return kv->key[p.i] == s.key && kv->values[p.j][p.i] == s.value &&
	       kv->n_values == s.n_values;
}

static bool zeroed(const struct tree_selector_kv *kv, struct probe p)
{
	return !kv->key[p.i] && !kv->values[p.j][p.i] && !kv->n_values;
}

static void add(void)
{
	struct tree_selector_kv *kvs, *was, *kv = NULL;
	struct probe p = any_probe();
	int n = LEN, max, ret, e;
	struct sample kept;

	__CPROVER_assume(max >= 0 && e >= 0 && e < LEN + !LEN);
	kvs = pairs(n);
	was = kvs;
	if (n)
		kept = sample(&kvs[e], p);
	ret = tree_selector_kv_add(&kvs, &n, max, &kv);
	if (ret) {
		__CPROVER_assert(kvs == was && n == LEN && !kv,
				 "a refusal changes nothing");
		__CPROVER_assert((ret == -E2BIG) == (max <= LEN),
				 "-E2BIG exactly at the limit");
		return;
	}
	__CPROVER_assert(max > LEN && n == LEN + 1 && kv == kvs + LEN,
			 "one more pair, the new one handed back");
	__CPROVER_assert(zeroed(kv, p), "the new pair zeroed");
	__CPROVER_assert(!LEN || same(&kvs[e], kept, p),
			 "the pairs before it kept");
}

static void copy(void)
{
	struct tree_selector src, dst;

	src.n_kconfig = LEN;
	src.n_labels = LEN;
	src.kconfig = pairs(LEN);
	src.labels = pairs(LEN);
	if (tree_selector_copy(&dst, &src)) {
		__CPROVER_assert(!dst.kconfig && !dst.labels && !dst.n_kconfig &&
				 !dst.n_labels, "a failed copy holds nothing");
		return;
	}
	__CPROVER_assert(dst.n_kconfig == LEN && dst.n_labels == LEN,
			 "as many pairs");
	__CPROVER_assert(!LEN || (dst.kconfig != src.kconfig &&
				  dst.labels != src.labels),
			 "pairs of its own");
	tree_selector_free(&dst);
	__CPROVER_assert(!dst.kconfig && !dst.labels && !dst.n_kconfig &&
			 !dst.n_labels, "a freed selector holds nothing");
}

void harness(void)
{
	text();
	add();
	copy();
}
