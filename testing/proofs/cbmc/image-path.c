// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * image_path_valid() of util/image_bootstrap.c, which vets the image paths
 * of the bootstrap settings, on every string of up to LEN_MAX bytes: what it
 * accepts is absolute, not the root and has no empty or ".." component but
 * a last empty one, and it accepts every absolute path of plain components.
 */

#include "proof.h"
#include "../../../util/image_bootstrap.c"

#define LEN_MAX	8

static bool component_is(const char *s, size_t n, const char *what)
{
	return span_equals_str(s, n, what);
}

void harness(void)
{
	bool plain = true, safe = true;
	size_t len, start, i, n;
	char *path, *s;

	s = any_bytes(LEN_MAX + 1);
	s[LEN_MAX] = '\0';
	__CPROVER_assume(len <= LEN_MAX);
	path = s + LEN_MAX - len;
	len = strlen(path);
	for (start = 1; start <= len; start = i + 1) {
		for (i = start; i < len && path[i] != '/'; i++)
			;
		n = i - start;
		plain = plain && n && !component_is(path + start, n, ".") &&
			!component_is(path + start, n, "..");
		safe = safe && !component_is(path + start, n, "..") &&
		       (n || i == len);
	}
	if (image_path_valid(path))
		__CPROVER_assert(path[0] == '/' && len > 1 && safe,
				 "absolute, not the root, no traversal");
	if (len && path[0] == '/' && plain)
		__CPROVER_assert(image_path_valid(path),
				 "every absolute path of plain components");
}
