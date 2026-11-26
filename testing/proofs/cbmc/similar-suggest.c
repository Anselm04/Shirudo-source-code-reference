// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * suggest() of util/similar.c on a word and up to two commands whose
 * lengths LEN encodes: the suggestions are commands within the cap, each
 * with its distance, nearest first, within the capacity, none nearer left
 * out. strlen() is given the lengths to keep the loops' bounds concrete.
 */

#include <stdbool.h>

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/similar.c"

#define N_MAX	2
#define CAP_MAX	2

static const size_t lens[N_MAX] = { LEN / 3 % 3, LEN / 9 };
static const char *table[N_MAX], *word;

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

size_t strlen(const char *s)
{
	if (s == word)
		return LEN % 3;
	__CPROVER_assert(s == table[0] || s == table[1], "a string of ours");
	return lens[s == table[1]];
}

void harness(void)
{
	struct suggestion *out;
	size_t n, cap, k, i, j;
	int dist[N_MAX], max;

	word = any_string(LEN % 3);
	table[0] = any_string(lens[0]);
	table[1] = any_string(lens[1]);
	__CPROVER_assume(n <= N_MAX && cap <= CAP_MAX && max >= 1 && max <= 3);
	out = cap == 2 ? any_bytes(2 * sizeof(*out)) :
	      cap == 1 ? any_bytes(sizeof(*out)) : any_bytes(0);
	k = suggest(word, table, n, max, out, cap);
	for (j = 0; j < n; j++)
		dist[j] = edit_distance(word, table[j], max);
	__CPROVER_assert(k <= cap && k <= n, "no more than fit, or exist");
	for (i = 0; i < k; i++) {
		for (j = 0; j < n && table[j] != out[i].name; j++)
			;
		__CPROVER_assert(j < n, "a command of the table");
		__CPROVER_assert(out[i].dist == dist[j] && dist[j] <= max,
				 "its distance, within the cap");
		__CPROVER_assert(!i || out[i - 1].dist <= out[i].dist,
				 "nearest first");
	}
	for (j = 0; j < n; j++) {
		for (i = 0; i < k && out[i].name != table[j]; i++)
			;
		__CPROVER_assert(dist[j] > max || i < k ||
				 (k == cap &&
				  (!cap || out[cap - 1].dist <= dist[j])),
				 "none nearer is left out");
	}
}
