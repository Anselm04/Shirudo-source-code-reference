// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The pairs and digests of util/bpm_tree_state.c: kv_add() stores a pair
 * whole or not at all, for keys and values of LEN bytes, kv_value() and
 * selector_values_match() are kvValue and listHolds of
 * testing/proofs/lean4/Shirudo/TreeOverlap.lean, and hex32_valid() takes
 * exactly 64 hex digits.
 */

/* util/malloc.c and util/string.c behind a file that includes their headers. */
#define MALLOC_INTERNAL
#define STRING_INTERNAL

/* CBMC's own memcpy() of a length it does not know runs out of memory. */
#define PROOF_MEMCPY_BYTEWISE

#include "proof.h"
#include "../../../util/bpm_tree_state.c"
#include "../../../util/hex.c"
#include "../../../util/string.c"
#include "bpm-tree-overlap-model.h"

#define PAIRS_MAX	2
#define TEXT_MAX	2

/* No harness here holds a selector against a node. */
static const char *model_kconfig(const char *key)
{
	return NULL;
}

/*
 * A string of exactly len bytes: any bytes while it is short, and one
 * byte repeated when it is long, which keeps its length a constant to
 * CBMC and the copy of it cheap.
 */
static char *string_of(size_t len)
{
	char *s = any_bytes(len + 1);

	if (len > TEXT_MAX)
		memset(s, 'k', len);
	else
		__CPROVER_assume(strnlen(s, len) == len);
	s[len] = '\0';
	return s;
}

/*
 * read_config_stream() adds to the max pairs of labels[] from a count
 * that starts at 0 and that only kv_add() moves, so n is at most max and
 * max the pairs there are.
 */
static void pair_added(size_t key_len, size_t value_len, int n)
{
	/*
	 * As bytes: CBMC 5.95 reads wrong bytes at an offset that depends
	 * on the data from an object whose type starts with an array of
	 * char, as an array of pairs does.
	 */
	char pairs[PAIRS_MAX * sizeof(struct tree_kv)];
	struct tree_kv *dst = (struct tree_kv *)pairs;
	char *key = string_of(key_len), *value = string_of(value_len);
	char kept_key, kept_value, new_key, new_value;
	const int was = n, last = PAIRS_MAX - 1;
	size_t at, k, v;
	int max, ret;

	__CPROVER_assume(max >= n && max <= PAIRS_MAX &&
			 at < TREE_STRING_MAX && k <= key_len &&
			 v <= value_len);
	kept_key = dst[0].key[at];
	kept_value = dst[0].value[at];
	new_key = dst[last].key[at];
	new_value = dst[last].value[at];
	ret = kv_add(dst, &n, max, key, value);
	if (ret) {
		__CPROVER_assert(ret == -E2BIG || ret == -ENOSPC,
				 "refused as full or as too long");
		__CPROVER_assert((ret == -E2BIG) == (was >= max),
				 "-E2BIG exactly at the limit");
		__CPROVER_assert(ret != -ENOSPC || LEN >= TREE_STRING_MAX,
				 "-ENOSPC only for a string that does not fit");
		__CPROVER_assert(n == was, "a refused pair is not counted");
		__CPROVER_assert(ret != -E2BIG ||
				 (dst[last].key[at] == new_key &&
				  dst[last].value[at] == new_value),
				 "nothing written at the limit");
	} else {
		__CPROVER_assert(was < max && LEN < TREE_STRING_MAX,
				 "taken below the limit, when both fit");
		__CPROVER_assert(n == was + 1, "counted once");
		__CPROVER_assert(dst[was].key[k] == key[k] &&
				 dst[was].value[v] == value[v],
				 "the key and the value stored whole");
	}
	__CPROVER_assert(!was || (dst[0].key[at] == kept_key &&
				  dst[0].value[at] == kept_value),
			 "the pairs before it kept");
}

static void short_text(const char *s)
{
	__CPROVER_assume(!s[TEXT_MAX]);
}

static void value_found(void)
{
	char *key = any_bytes(TEXT_MAX + 1);
	struct tree_kv v[PAIRS_MAX];
	int n;

	__CPROVER_assume(n >= 0 && n <= PAIRS_MAX);
	short_text(key);
	for (int i = 0; i < PAIRS_MAX; i++) {
		short_text(v[i].key);
		short_text(v[i].value);
	}
	__CPROVER_assert(kv_value(v, n, key) == model_kv_value(v, n, key),
			 "kvValue of the model: the first pair with the key");
}

static void values_matched(void)
{
	char *want = any_bytes(TEXT_MAX + 1);
	struct tree_selector_kv pair;
	bool no_pair, no_want;
	int ret;

	__CPROVER_assume(pair.n_values >= 0 && pair.n_values <= PAIRS_MAX);
	short_text(want);
	for (int i = 0; i < PAIRS_MAX; i++)
		short_text(pair.values[i]);
	ret = selector_values_match(no_pair ? NULL : &pair,
				    no_want ? NULL : want);
	__CPROVER_assert(ret == (!no_pair && !no_want &&
				 model_list_holds(pair.values, pair.n_values,
						  want)),
			 "listHolds of the model, and nothing without a value");
}

static void digest_valid(void)
{
	char *hex = any_bytes(66);
	bool digits = true;
	size_t i;

	hex[65] = '\0';
	for (i = 0; i < 64; i++)
		digits &= (hex[i] >= '0' && hex[i] <= '9') ||
			  (hex[i] >= 'a' && hex[i] <= 'f') ||
			  (hex[i] >= 'A' && hex[i] <= 'F');
	__CPROVER_assert(hex32_valid(hex) == (digits && !hex[64]),
			 "exactly 64 hex digits");
}

void harness(void)
{
	const size_t len = LEN;

	/* The count decides nothing once a pair is below the limit. */
	for (int n = 0; n <= (len > TEXT_MAX ? 0 : PAIRS_MAX); n++) {
		pair_added(LEN, 1, n);
		pair_added(1, LEN, n);
	}
	if (LEN == 1) {
		value_found();
		values_matched();
		digest_valid();
	}
}
