// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What tree_parse() of util/bpm_tree.c keeps of a publication from a
 * registry, as its parser hands it over: a kconfig or label key only once,
 * with a value and below its limit, and an operation only whole, with a
 * positive seq, no empty selector list and room in the publication. And
 * the publications tree_publication_check() then accepts: a parent that is
 * none or a "sha256:" digest, a base at 0 without the segment keys, past 0
 * with an operation, a "sha256:" digest and a root of 64 hex digits each,
 * and operations that run from the base to the head.
 */

/* util/malloc.c and util/string.c behind a file that includes their headers. */
#define MALLOC_INTERNAL
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/hex.c"
#include "../../../util/bpm_tree.c"
#include "../../../util/malloc.c"
#include "../../../util/string.c"

#define TEXT_MAX	3

static void map_pair(void)
{
	struct tree_reader reader, *r = &reader;
	struct tree_selector_kv *kvs = NULL;
	struct tree_map m = { r, &kvs, NULL, 0 };
	int n = LEN, n_pair = r->n_pair, max;
	char *key = any_bytes(TEXT_MAX + 1);
	bool known = false;
	size_t i, j;
	int ret;

	m.n = &n;
	m.max = max;
	__CPROVER_assume(max >= 0 && n_pair >= 0 &&
			 n_pair <= TREE_MAX_SELECTOR_VALUES && !key[TEXT_MAX] &&
			 i < TREE_STRING_MAX && j < TREE_MAX_SELECTOR_VALUES);
	if (LEN) {
		kvs = __CPROVER_allocate(sizeof(*kvs), 0);
		__CPROVER_assume(kvs && !kvs[0].key[TEXT_MAX]);
		known = !strcmp(kvs[0].key, key);
	}
	ret = tree_map_pair(&m, key);
	if (ret) {
		__CPROVER_assert(!n_pair || known || max <= LEN ||
				 ret == -ENOMEM,
				 "refused without a value, twice or at the limit");
		__CPROVER_assert(n == LEN, "a refused key is not counted");
		return;
	}
	__CPROVER_assert(n_pair && !known && max > LEN,
			 "a new key with a value, below the limit");
	__CPROVER_assert(n == LEN + 1 && !strcmp(kvs[LEN].key, key) &&
			 kvs[LEN].n_values == n_pair &&
			 kvs[LEN].values[j][i] == r->pair[j][i] && !r->n_pair,
			 "the key with its values, the next pair empty");
}

static void take_operation(void)
{
	struct tree_reader reader, *r = &reader;
	struct tree_operation *o = &r->op;
	const struct tree_selector *s = &o->selector;
	struct tree_publication pub = {};
	struct json_field lists[3];
	bool whole, lists_ok;
	__s64 seq = o->seq;
	size_t i;
	char id;
	int ret;

	r->pub = &pub;
	r->lists = lists;
	o->selector.kconfig = NULL;
	o->selector.n_kconfig = 0;
	o->selector.labels = NULL;
	o->selector.n_labels = 0;
	pub.n_operations = LEN ? TREE_MAX_OPS : 0;
	pub.operations_capacity = LEN ? TREE_MAX_OPS : 1;
	if (!LEN) {
		pub.operations = __CPROVER_allocate(sizeof(*pub.operations), 0);
		__CPROVER_assume(pub.operations);
	}
	__CPROVER_assume(s->n_kernel_release_prefix >= 0 &&
			 s->n_kernel_build_id >= 0 && s->n_architecture >= 0 &&
			 i < sizeof(o->id));
	id = o->id[i];
	whole = o->id[0] && o->op[0] && seq > 0 && o->operation_digest[0] &&
		o->artifact.repository[0] && o->artifact.manifest_digest[0] &&
		o->artifact.layer_digest[0] && o->artifact.payload_sha256[0];
	lists_ok = (!lists[0].seen || s->n_kernel_release_prefix) &&
		   (!lists[1].seen || s->n_kernel_build_id) &&
		   (!lists[2].seen || s->n_architecture);
	ret = tree_take_operation(r);
	if (ret) {
		__CPROVER_assert(!whole || !lists_ok || LEN || ret == -ENOMEM,
				 "only a broken operation or a full tree refused");
		__CPROVER_assert(pub.n_operations == (LEN ? TREE_MAX_OPS : 0),
				 "a refused operation is not counted");
		return;
	}
	__CPROVER_assert(whole && lists_ok && !LEN,
			 "a whole operation kept, while room");
	__CPROVER_assert(pub.n_operations == 1 &&
			 pub.operations[0].seq == seq &&
			 pub.operations[0].id[i] == id,
			 "the operation kept");
	__CPROVER_assert(!o->seq && !o->id[0] && !o->selector.kconfig &&
			 !o->selector.labels,
			 "the next operation read into a cleared one");
}

static bool hex_digits(const char *s)
{
	for (int i = 0; i < 64; i++)
		if (!((s[i] >= '0' && s[i] <= '9') ||
		      (s[i] >= 'a' && s[i] <= 'f') ||
		      (s[i] >= 'A' && s[i] <= 'F')))
			return false;
	return !s[64];
}

static bool sha256_named(const char *s)
{
	return str_skip_prefix(&s, "sha256:") && hex_digits(s);
}

/* LEN operations, any parent, any base and head, the first at any seq. */
static void check(void)
{
	struct tree_operation *op = any_bytes(sizeof(*op));
	struct tree_publication pub;
	bool named, keys, runs, parent;
	__s64 base, head, first;
	int ret;

	__CPROVER_assume(base >= 0 && base < INT64_MAX);
	pub.base_seq = base;
	pub.operations = op;
	pub.n_operations = LEN;
	pub.head_seq = head;
	op->seq = first;
	/* As the parser leaves them. */
	pub.parent_manifest_digest[sizeof(pub.parent_manifest_digest) - 1] =
		'\0';
	pub.segment_manifest_digest[sizeof(pub.segment_manifest_digest) - 1] =
		'\0';
	pub.history_root[sizeof(pub.history_root) - 1] = '\0';
	ret = tree_publication_check(&pub);
	parent = !pub.parent_manifest_digest[0] ||
		 sha256_named(pub.parent_manifest_digest);
	keys = pub.segment_manifest_digest[0] || pub.history_root[0];
	named = sha256_named(pub.segment_manifest_digest) &&
		hex_digits(pub.history_root);
	runs = LEN ? first == base + 1 && head == first : head == base;
	__CPROVER_assert(ret == 0 || ret == -EINVAL, "0 or -EINVAL");
	__CPROVER_assert(!ret == (parent && runs &&
				  (base ? LEN && named : !keys)),
			 "a parent that is none or a digest, the first segment "
			 "without the segment keys, a later one with an "
			 "operation and both keys well formed, and operations "
			 "from the base to the head");
}

void harness(void)
{
	map_pair();
	take_operation();
	check();
}
