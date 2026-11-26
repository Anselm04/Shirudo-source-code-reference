// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_semver_compare() of util/bpm_package.c on every pair of strings of up
 * to STR_MAX bytes: antisymmetric, a tie only for versions apart in build
 * metadata, every SemVer version above any other string, and major, minor
 * and patch deciding by number before a pre-release ranks below its
 * release.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_package.c"
#include "../../../util/string.c"

#define STR_MAX	7

static char *any_string(void)
{
	char *s = any_bytes(STR_MAX + 1);

	__CPROVER_assume(!s[STR_MAX]);
	return s;
}

/* The part precedence reads: up to a build's '+', or all of it. */
static size_t precedence_len(const char *s)
{
	size_t i;

	for (i = 0; s[i] && s[i] != '+'; i++)
		;
	return i;
}

static size_t core_len(const char *s)
{
	size_t i;

	for (i = 0; s[i] && s[i] != '+' && s[i] != '-'; i++)
		;
	return i;
}

static bool same_prefix(const char *a, size_t la, const char *b, size_t lb)
{
	size_t i;

	if (la != lb)
		return false;
	for (i = 0; i < la; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

static size_t field_len(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len && s[i] != '.'; i++)
		;
	return i;
}

/*
 * Numbers without leading zeros: the longer is larger, and of two as long
 * the first digit that differs decides.
 */
static int number_order(const char *a, size_t la, const char *b, size_t lb)
{
	size_t i;

	if (la != lb)
		return la < lb ? -1 : 1;
	for (i = 0; i < la; i++)
		if (a[i] != b[i])
			return a[i] < b[i] ? -1 : 1;
	return 0;
}

/* Major, minor and patch of two valid cores, in that order. */
static int core_order(const char *a, const char *b)
{
	size_t la = core_len(a), lb = core_len(b), na, nb;
	int part, c;

	for (part = 0; part < 3; part++) {
		na = field_len(a, la);
		nb = field_len(b, lb);
		c = number_order(a, na, b, nb);
		if (c || part == 2)
			return c;
		a += na + 1;
		la -= na + 1;
		b += nb + 1;
		lb -= nb + 1;
	}
	return 0;
}

static void pair(void)
{
	char *a = any_string(), *b = any_string();
	bool va = bpm_semver_valid(a), vb = bpm_semver_valid(b);
	int ab = bpm_semver_compare(a, b), ba = bpm_semver_compare(b, a);
	size_t ca = core_len(a), cb = core_len(b);
	bool tie;

	__CPROVER_assert(ab >= -1 && ab <= 1, "below, equal or above");
	__CPROVER_assert(ab == -ba, "antisymmetric");
	tie = va && vb ?
	      same_prefix(a, precedence_len(a), b, precedence_len(b)) :
	      !strcmp(a, b);
	__CPROVER_assert(!ab == tie,
			 "a tie only for versions apart in build metadata");
	if (va != vb)
		__CPROVER_assert(ab == (va ? 1 : -1),
				 "a SemVer version above any other string");
	if (!va || !vb)
		return;
	if (!same_prefix(a, ca, b, cb))
		__CPROVER_assert(ab == core_order(a, b),
				 "major, minor and patch decide by number");
	else if (a[ca] == '-' && b[cb] != '-')
		__CPROVER_assert(ab == -1,
				 "a pre-release below the release of its core");
}

void harness(void)
{
	pair();
}
