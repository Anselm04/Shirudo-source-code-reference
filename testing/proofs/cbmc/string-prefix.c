// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The prefix and span compares of <shirudo/string.h> on every string of
 * up to LEN_MAX bytes and every prefix of up to PREFIX_MAX:
 * str_after_prefix() gives the rest exactly where the string starts with
 * the prefix, in either case for the _nocase forms, span_equals_str() is
 * true exactly for the string's own bytes, and the span forms read the
 * span's len bytes alone.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define LEN_MAX		5
#define PREFIX_MAX	3

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

/* Whether the n bytes at a and b are the same, or the same letters. */
static bool same(const char *a, const char *b, size_t n, bool nocase)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (nocase ? lower(a[i]) != lower(b[i]) : a[i] != b[i])
			return false;
	return true;
}

static void rest_after_a_prefix(void)
{
	const char *s, *prefix, *rest;
	size_t len, n;

	__CPROVER_assume(len <= LEN_MAX && n <= PREFIX_MAX);
	s = any_string(len);
	prefix = any_string(n);
	rest = str_after_prefix(s, prefix);
	__CPROVER_assert(rest == (n <= len && same(s, prefix, n, false) ?
				  s + n : NULL),
			 "the rest where the string starts with the prefix");
	rest = str_after_prefix_nocase(s, prefix);
	__CPROVER_assert(rest == (n <= len && same(s, prefix, n, true) ?
				  s + n : NULL),
			 "the rest where it does in either case");
}

static void literal_prefix_in_either_case(void)
{
	const char *s, *p;
	size_t len, n;
	bool starts;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_string(len);
	starts = len >= 3 && same(s, "a-z", 3, true);
	n = str_has_prefix_nocase(s, "A-z");
	__CPROVER_assert(n == (starts ? 3 : 0), "the literal's length, or 0");
	p = s;
	__CPROVER_assert(str_skip_prefix_nocase(&p, "a-Z") == starts &&
			 p == s + n, "past the prefix on a match alone");
}

static void span_of_exactly_its_bytes(void)
{
	size_t len, n, has;
	const char *str;
	char *span;

	__CPROVER_assume(len <= LEN_MAX && n <= PREFIX_MAX);
	span = any_bytes(len);
	str = any_string(n);
	__CPROVER_assert(span_equals_str(span, len, str) ==
			 (len == n && same(span, str, n, false)),
			 "the span is the string, no more and no fewer");
	has = span_has_prefix_nocase(span, len, "a-z");
	__CPROVER_assert(has == (len >= 3 && same(span, "A-Z", 3, true) ?
				 3 : 0),
			 "the literal's length where the span starts with it");
}

void harness(void)
{
	rest_after_a_prefix();
	literal_prefix_in_either_case();
	span_of_exactly_its_bytes();
}
