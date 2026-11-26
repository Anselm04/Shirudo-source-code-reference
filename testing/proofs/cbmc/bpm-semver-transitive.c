// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_semver_compare() of util/bpm_package.c is transitive over every three
 * strings of up to STR_MAX bytes, SemVer versions or not, so that with its
 * antisymmetry it orders every version a repository can name.
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

void harness(void)
{
	char *a = any_string(), *b = any_string(), *c = any_string();

	if (bpm_semver_compare(a, b) <= 0 && bpm_semver_compare(b, c) <= 0)
		__CPROVER_assert(bpm_semver_compare(a, c) <= 0, "transitive");
}
