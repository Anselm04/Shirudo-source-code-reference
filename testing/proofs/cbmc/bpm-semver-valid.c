// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_semver_valid() of util/bpm_package.c on every string of up to
 * STR_MAX bytes: it takes exactly the versions of the SemVer 2.0.0
 * grammar, and the pre-release it finds in one is the part between the
 * core and any build.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_package.c"
#include "../../../util/string.c"

#define STR_MAX	11

static bool digit(char c)
{
	return c >= '0' && c <= '9';
}

static bool ident_char(char c)
{
	return digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       c == '-';
}

static bool numeric(const char *s, size_t from, size_t to)
{
	size_t i;

	for (i = from; i < to; i++)
		if (!digit(s[i]))
			return false;
	return true;
}

/* <numeric identifier>: "0", or digits that do not start with 0. */
static bool numeric_identifier(const char *s, size_t from, size_t to)
{
	return from < to && numeric(s, from, to) &&
	       (to - from == 1 || s[from] != '0');
}

/* Dot-separated identifiers; a numeric pre-release one has no leading 0. */
static bool identifiers(const char *s, size_t from, size_t to, bool pre)
{
	size_t start = from, i;

	for (i = from; i <= to; i++) {
		if (i < to && s[i] != '.') {
			if (!ident_char(s[i]))
				return false;
			continue;
		}
		if (i == start)
			return false;
		if (pre && numeric(s, start, i) &&
		    !numeric_identifier(s, start, i))
			return false;
		start = i + 1;
	}
	return true;
}

/* <version core>: three numeric identifiers and two dots. */
static bool core(const char *s, size_t to)
{
	size_t start = 0, parts = 0, i;

	for (i = 0; i <= to; i++) {
		if (i < to && s[i] != '.')
			continue;
		if (!numeric_identifier(s, start, i))
			return false;
		parts++;
		start = i + 1;
	}
	return parts == 3;
}

static size_t first(const char *s, size_t len, char c)
{
	size_t i;

	for (i = 0; i < len && s[i] != c; i++)
		;
	return i;
}

void harness(void)
{
	size_t len, plus, minus;
	struct semver v;
	bool grammar;
	char *s;

	s = any_bytes(STR_MAX + 1);
	__CPROVER_assume(!s[STR_MAX]);
	len = strnlen(s, STR_MAX);
	plus = first(s, len, '+');
	minus = first(s, plus, '-');
	grammar = core(s, minus) &&
		  (minus == plus || identifiers(s, minus + 1, plus, true)) &&
		  (plus == len || identifiers(s, plus + 1, len, false));
	__CPROVER_assert(bpm_semver_valid(s) == grammar,
			 "exactly the SemVer 2.0.0 versions are valid");
	if (!semver_parse(s, &v))
		return;
	__CPROVER_assert(minus == plus ?
			 !v.pre_len :
			 v.pre == s + minus + 1 && v.pre_len == plus - minus - 1,
			 "the pre-release between the core and the build");
}
