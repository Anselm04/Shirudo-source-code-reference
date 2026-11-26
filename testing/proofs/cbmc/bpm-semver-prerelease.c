// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The pre-release order of util/bpm_package.c, SemVer 2.0.0 11.4, on every
 * pair of valid pre-releases of up to LIST_MAX bytes: identifiers compare
 * left to right, numeric ones by value and below alphanumeric ones, those
 * by their ASCII bytes, and a list after a shorter one it starts with.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_package.c"
#include "../../../util/string.c"

#define IDENT_MAX	3
#define LIST_MAX	5

static bool digit(char c)
{
	return c >= '0' && c <= '9';
}

static bool ident_char(char c)
{
	return digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       c == '-';
}

static bool numeric(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (!digit(s[i]))
			return false;
	return true;
}

/* Dot-separated identifiers; a numeric one has no leading 0. */
static bool valid(const char *s, size_t len)
{
	size_t start = 0, i;

	for (i = 0; i <= len; i++) {
		if (i < len && s[i] != '.') {
			if (!ident_char(s[i]))
				return false;
			continue;
		}
		if (i == start || (numeric(s + start, i - start) &&
				   i - start > 1 && s[start] == '0'))
			return false;
		start = i + 1;
	}
	return true;
}

static __u32 value(const char *s, size_t len)
{
	__u32 v = 0;
	size_t i;

	for (i = 0; i < len; i++)
		v = v * 10 + (__u32)(s[i] - '0');
	return v;
}

static int ascii_order(const char *a, size_t la, const char *b, size_t lb)
{
	size_t i;

	for (i = 0; i < la && i < lb; i++)
		if (a[i] != b[i])
			return (__u8)a[i] < (__u8)b[i] ? -1 : 1;
	return la == lb ? 0 : la < lb ? -1 : 1;
}

static size_t first_len(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len && s[i] != '.'; i++)
		;
	return i;
}

static char *list(size_t *len, size_t max)
{
	char *s = any_bytes(max);

	__CPROVER_assume(*len <= max && valid(s, *len));
	return s;
}

/* 11.4.1 to 11.4.3: one identifier against another. */
static void identifier(void)
{
	size_t la, lb;
	char *a = list(&la, IDENT_MAX), *b = list(&lb, IDENT_MAX);
	bool na = numeric(a, la), nb = numeric(b, lb);
	__u32 va, vb;
	int c;

	__CPROVER_assume(first_len(a, la) == la && first_len(b, lb) == lb);
	c = prerelease_compare(a, la, b, lb);
	if (na && nb) {
		va = value(a, la);
		vb = value(b, lb);
		__CPROVER_assert(c == (va == vb ? 0 : va < vb ? -1 : 1),
				 "numeric identifiers by value");
	} else if (na != nb) {
		__CPROVER_assert(c == (na ? -1 : 1),
				 "a numeric identifier below an alphanumeric one");
	} else {
		__CPROVER_assert(c == ascii_order(a, la, b, lb),
				 "alphanumeric identifiers by their ASCII bytes");
	}
}

/* 11.4: the first identifiers that differ decide, else the longer list. */
static void lists(void)
{
	size_t la, lb, fa, fb;
	char *a = list(&la, LIST_MAX), *b = list(&lb, LIST_MAX);
	int c;

	__CPROVER_assume(la && lb);
	c = prerelease_compare(a, la, b, lb);
	__CPROVER_assert(c == -prerelease_compare(b, lb, a, la),
			 "antisymmetric");
	fa = first_len(a, la);
	fb = first_len(b, lb);
	if (fa != fb || memcmp(a, b, fa))
		__CPROVER_assert(c == prerelease_compare(a, fa, b, fb),
				 "the first identifiers decide when they differ");
	else if (fa < la && fb < lb)
		__CPROVER_assert(c == prerelease_compare(a + fa + 1,
							 la - fa - 1,
							 b + fb + 1,
							 lb - fb - 1),
				 "else the rest of the lists");
	else
		__CPROVER_assert(c == (la == lb ? 0 : la < lb ? -1 : 1),
				 "else the longer list, with more identifiers");
}

void harness(void)
{
	identifier();
	lists();
}
