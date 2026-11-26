// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * resolve() of util/similar.c on every word of up to LEN_MAX bytes
 * against every table of up to N_MAX such words: a word resolves to the
 * first command that is the word, else to the commands it begins, else
 * to those that begin it, in table order and never past the capacity.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/similar.c"

#define N_MAX	3
#define LEN_MAX	2
#define CAP_MAX	2

static const char *table[N_MAX];
static size_t lens[N_MAX];

static char *any_string(size_t *len)
{
	char *s;

	__CPROVER_assume(*len <= LEN_MAX);
	s = any_bytes(*len + 1);
	__CPROVER_assume(!s[*len] && strnlen(s, *len) == *len);
	return s;
}

static size_t any_table(void)
{
	size_t n, i;

	__CPROVER_assume(n <= N_MAX);
	for (i = 0; i < n; i++) {
		size_t len;

		table[i] = any_string(&len);
		lens[i] = len;
	}
	return n;
}

static bool begins(const char *word, size_t len, const char *with, size_t n)
{
	return n < len && !memcmp(word, with, n);
}

static void resolved(void)
{
	size_t n = any_table(), len, cap, k, i, tier;
	size_t exact = N_MAX, longer = 0, shorter = 0;
	char *input = any_string(&len);
	size_t *matches;

	__CPROVER_assume(cap <= CAP_MAX);
	matches = any_bytes(cap * sizeof(*matches));
	k = resolve(input, table, n, matches, cap);
	for (i = n; i-- > 0; ) {
		if (lens[i] == len && !memcmp(input, table[i], len))
			exact = i;
		longer += begins(table[i], lens[i], input, len);
		shorter += begins(input, len, table[i], lens[i]);
	}
	if (exact < N_MAX) {
		__CPROVER_assert(k == 1 && (!cap || matches[0] == exact),
				 "the first command that is the word");
		return;
	}
	tier = longer ? longer : shorter;
	__CPROVER_assert(k == min(tier, cap),
			 "the first tier that hits, up to the capacity");
	for (i = 0; i < k; i++) {
		size_t j = matches[i];

		__CPROVER_assert(j < n, "an index of the table");
		__CPROVER_assert(!i || matches[i - 1] < j, "in table order");
		__CPROVER_assert(longer ?
				 begins(table[j], lens[j], input, len) :
				 begins(input, len, table[j], lens[j]),
				 "of that tier");
	}
}

void harness(void)
{
	resolved();
}
