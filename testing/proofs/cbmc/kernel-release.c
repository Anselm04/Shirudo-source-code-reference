// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * kernel_release_prefix_matches() of util/kernel_release.c, which picks a
 * tree's upatches for the running kernel, on every release and prefix of up
 * to LEN_MAX characters: it matches exactly a prefix that ends where the
 * release does or at a '.' or '-', and reads nothing past either string.
 */

#include "proof.h"
#include "../../../util/kernel_release.c"

#define LEN_MAX	8

static char *any_string(void)
{
	char *s = any_bytes(LEN_MAX + 1);
	size_t len;

	__CPROVER_assume(len <= LEN_MAX);
	s[LEN_MAX] = '\0';
	return s + LEN_MAX - len;
}

void harness(void)
{
	char *release = any_string(), *prefix = any_string();
	size_t n = strlen(prefix), i;
	bool starts = strlen(release) >= n;

	for (i = 0; starts && i < n; i++)
		starts = release[i] == prefix[i];
	__CPROVER_assert(kernel_release_prefix_matches(release, prefix) ==
			 (!n || (starts && (!release[n] || release[n] == '.' ||
					    release[n] == '-'))),
			 "a prefix ending at a component boundary");
}
