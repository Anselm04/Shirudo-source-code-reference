// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * path_join() and format_key_path() of util/paths.c on parts of up to
 * LEN_MAX bytes and every buffer size: a path is its parts with one slash
 * between them, terminated, exactly when it fits, and -ENAMETOOLONG
 * otherwise, with an empty string from path_join(); a key path takes no
 * second slash after a directory that ends in one.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/paths.c"

#define LEN_MAX	2

static char *any_string(size_t *len)
{
	char *s;

	__CPROVER_assume(*len <= LEN_MAX);
	s = any_bytes(*len + 1);
	__CPROVER_assume(!s[*len] && strnlen(s, *len) == *len);
	return s;
}

/* Whether out holds part at off, and then what follows it. */
static size_t holds(const char *out, size_t off, const char *part,
		    size_t len)
{
	__CPROVER_assert(!memcmp(out + off, part, len), "the part, as given");
	return off + len;
}

static void joined(void)
{
	size_t ld, ln, cap, off;
	char *dir, *name, *out;
	int ret;

	dir = any_string(&ld);
	name = any_string(&ln);
	__CPROVER_assume(cap <= 2 * LEN_MAX + 3);
	out = any_bytes(cap);
	ret = path_join(out, cap, dir, name);
	__CPROVER_assert(!ret || ret == -ENAMETOOLONG, "0 or -ENAMETOOLONG");
	__CPROVER_assert(!ret == (ld + 1 + ln < cap), "exactly when it fits");
	if (ret) {
		__CPROVER_assert(!cap || !out[0], "empty on refusal");
		return;
	}
	off = holds(out, 0, dir, ld);
	__CPROVER_assert(out[off++] == '/', "one slash");
	off = holds(out, off, name, ln);
	__CPROVER_assert(!out[off], "terminated");
}

static void key_path(void)
{
	size_t ld, lf, cap, off, sep;
	char *dir, *file, *out;
	bool valid;
	int ret;

	dir = any_string(&ld);
	file = any_string(&lf);
	__CPROVER_assume(cap <= 2 * LEN_MAX + 3);
	out = any_bytes(cap);
	ret = format_key_path(out, cap, dir, file);
	valid = cap && ld && lf;
	sep = ld && dir[ld - 1] != '/';
	__CPROVER_assert((ret == -EINVAL) == !valid,
			 "a buffer, a directory and a file, or -EINVAL");
	__CPROVER_assert(!ret == (valid && ld + sep + lf < cap),
			 "exactly when it fits");
	__CPROVER_assert(!ret || ret == -EINVAL || ret == -ENAMETOOLONG,
			 "0, -EINVAL or -ENAMETOOLONG");
	if (ret)
		return;
	off = holds(out, 0, dir, ld);
	if (sep)
		__CPROVER_assert(out[off++] == '/', "one slash, not two");
	off = holds(out, off, file, lf);
	__CPROVER_assert(!out[off], "terminated");
	__CPROVER_assert(format_key_path(NULL, cap, dir, file) == -EINVAL &&
			 format_key_path(out, cap, dir, NULL) == -EINVAL,
			 "no buffer or no file");
}

void harness(void)
{
	joined();
	key_path();
}
