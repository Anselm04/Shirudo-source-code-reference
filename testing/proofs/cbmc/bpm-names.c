// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The package, repository and version names util/bpm_oci.c accepts, for
 * every string of up to NAME_MAX bytes: a name or version is of letters,
 * digits, '.', '_' and '-', a version also '+', not empty, shorter than
 * BPM_MAX_NAME and not led by a dot, a package name led by a letter or digit.
 */

#include "proof.h"
#include "../../../util/bpm_oci.c"

#define NAME_MAX	(BPM_MAX_NAME + 1)

static bool alnum(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z');
}

static bool name_chars(const char *s, size_t len, bool plus)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (!alnum(s[i]) && s[i] != '.' && s[i] != '_' && s[i] != '-' &&
		    !(plus && s[i] == '+'))
			return false;
	return true;
}

void harness(void)
{
	char *s = any_bytes(NAME_MAX + 1);
	bool sized;
	size_t len;

	__CPROVER_assume(!s[NAME_MAX]);
	len = strnlen(s, NAME_MAX);
	sized = len && len < BPM_MAX_NAME;
	__CPROVER_assert(bpm_name_ok(s) ==
			 (sized && s[0] != '.' && name_chars(s, len, false)),
			 "a name");
	__CPROVER_assert(bpm_version_ok(s) ==
			 (sized && s[0] != '.' && name_chars(s, len, true)),
			 "a version");
	__CPROVER_assert(bpm_package_name_ok(s) ==
			 (sized && alnum(s[0]) && name_chars(s, len, false)),
			 "a package name");
}
