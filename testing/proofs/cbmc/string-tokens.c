// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * token_next() and for_each_token() of util/string.c on every span of LEN
 * bytes, every one or two delimiters and every cursor: a token lies
 * inside the span, holds no delimiter and has one or the span's end on
 * either side, the cursor ends past it, and a walk gives the bytes that
 * are no delimiter in order, each once, reading the span's bytes alone.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

static char delims[3];

static bool delimits(char c)
{
	return c == delims[0] || (delims[1] && c == delims[1]);
}

static void any_delims(void)
{
	char first, second;

	__CPROVER_assume(first);
	delims[0] = first;
	delims[1] = second;
}

static void one_token(const char *s)
{
	size_t pos, start, was, n, i;

	was = pos;
	n = token_next(s, LEN, delims, &pos, &start);
	__CPROVER_assert(start <= LEN && n <= LEN - start,
			 "a token inside the span");
	__CPROVER_assert(pos <= LEN && pos >= start + n && pos - start - n <= 1,
			 "the cursor past the token and one delimiter");
	for (i = 0; i < LEN; i++) {
		if (i >= was && i < start)
			__CPROVER_assert(delimits(s[i]),
					 "only delimiters before the token");
		if (i >= start && i < start + n)
			__CPROVER_assert(!delimits(s[i]),
					 "no delimiter in the token");
		if (i == start + n)
			__CPROVER_assert(delimits(s[i]) && pos == i + 1,
					 "a delimiter ends it, and is skipped");
	}
	__CPROVER_assert(n || start == LEN, "no token only at the span's end");
	__CPROVER_assert(was > LEN || start >= was,
			 "a token at or after the cursor");
}

static void whole_walk(const char *s)
{
	size_t n, i, seen = 0, want = 0, next = 0;
	const char *tok;

	for_each_token(tok, n, s, LEN, delims) {
		__CPROVER_assert(n && tok >= s + next &&
				 n <= LEN - (size_t)(tok - s),
				 "a token of a byte or more, past the last");
		next = (size_t)(tok - s) + n;
		seen += n;
	}
	for (i = 0; i < LEN; i++)
		want += !delimits(s[i]);
	__CPROVER_assert(seen == want, "every byte that is no delimiter");
}

void harness(void)
{
	const char *s = any_bytes(LEN);

	any_delims();
	one_token(s);
	whole_walk(s);
}
