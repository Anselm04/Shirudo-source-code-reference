// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * edit_distance() of util/similar.c on every two strings of LEN / 4 and
 * LEN % 4 bytes and every cap a caller passes: the Levenshtein distance
 * when it is within the cap, and more than the cap when it is not.
 */

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/similar.c"

#define M	(LEN / 4)
#define N	(LEN % 4)

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

/* The distance by its definition: the cheapest of the three last edits. */
static int distance(const char *s, size_t m, const char *t, size_t n)
{
	int best, d;

	if (!m)
		return (int)n;
	if (!n)
		return (int)m;
	best = distance(s + 1, m - 1, t + 1, n - 1) + (s[0] != t[0]);
	d = distance(s + 1, m - 1, t, n) + 1;
	if (d < best)
		best = d;
	d = distance(s, m, t + 1, n - 1) + 1;
	if (d < best)
		best = d;
	return best;
}

void harness(void)
{
	char *s = any_string(M), *t = any_string(N);
	int max, got, want;

	__CPROVER_assume(max >= 1 && max <= 3);
	got = edit_distance(s, t, max);
	want = distance(s, M, t, N);
	__CPROVER_assert(want <= max ? got == want : got > max,
			 "the distance, or more than the cap");
}
