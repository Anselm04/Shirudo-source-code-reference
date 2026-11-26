// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The searches of <shirudo/string.h> on every span of LEN bytes:
 * span_until() gives the length of what comes before the first byte of a
 * set of one or two, span_find() the first place a needle of up to
 * NEEDLE_MAX bytes lies in the span or NULL where it lies nowhere, both
 * reading the span's bytes alone, str_contains() says the same of a
 * string, and str_equals_nocase() is true exactly of two strings of the
 * same letters.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define NEEDLE_MAX	2

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

static char lower(char c)
{
	return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static void up_to_a_byte_of_a_set(const char *s)
{
	char set[3] = {};
	char first, second;
	size_t n, i;

	__CPROVER_assume(first);
	set[0] = first;
	set[1] = second;
	n = span_until(s, LEN, set);
	__CPROVER_assert(n <= LEN, "no longer than the span");
	for (i = 0; i < LEN; i++) {
		bool in_set = s[i] == set[0] || (set[1] && s[i] == set[1]);

		if (i < n)
			__CPROVER_assert(!in_set, "no byte of the set before");
		if (i == n)
			__CPROVER_assert(in_set, "a byte of the set ends it");
	}
}

/* Whether the m bytes of needle lie at s + at, inside the span. */
static bool lies_at(const char *s, size_t at, const char *needle, size_t m)
{
	size_t i;

	if (m > LEN || at > LEN - m)
		return false;
	for (i = 0; i < m; i++)
		if (s[at + i] != needle[i])
			return false;
	return true;
}

static void first_place_of_a_needle(const char *s)
{
	const char *needle, *found;
	size_t m, i;

	__CPROVER_assume(m <= NEEDLE_MAX);
	needle = any_string(m);
	found = span_find(s, LEN, needle);
	for (i = 0; i <= LEN; i++) {
		if (found && i < (size_t)(found - s))
			__CPROVER_assert(!lies_at(s, i, needle, m),
					 "no earlier place");
		if (!found)
			__CPROVER_assert(!lies_at(s, i, needle, m),
					 "NULL only where it lies nowhere");
	}
	__CPROVER_assert(!found || (found >= s &&
				    lies_at(s, (size_t)(found - s), needle, m)),
			 "the needle, inside the span");
}

static void strings(void)
{
	size_t a_len, b_len, m, i;
	const char *a, *b, *needle;
	bool same, lies = false;

	__CPROVER_assume(a_len <= 3 && b_len <= 3 && m <= NEEDLE_MAX);
	a = any_string(a_len);
	b = any_string(b_len);
	needle = any_string(m);
	same = a_len == b_len;
	for (i = 0; i < 3; i++)
		if (i < a_len && i < b_len && lower(a[i]) != lower(b[i]))
			same = false;
	__CPROVER_assert(str_equals_nocase(a, b) == same,
			 "the same letters, and as many");
	for (i = 0; i <= 3; i++) {
		size_t k;
		bool here = m <= a_len && i <= a_len - m;

		for (k = 0; k < NEEDLE_MAX; k++)
			if (here && k < m && a[i + k] != needle[k])
				here = false;
		lies = lies || here;
	}
	__CPROVER_assert(str_contains(a, needle) == lies,
			 "a string holds the needle where it lies in it");
}

void harness(void)
{
	const char *s = any_bytes(LEN);

	up_to_a_byte_of_a_set(s);
	first_place_of_a_needle(s);
	strings();
}
