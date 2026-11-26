// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * upatch_pin_path() of util/paths.c into a buffer of LEN bytes, for an
 * upatch name and up to two parts of a byte each or none: the pin
 * directory, the pin name and the parts with one slash before each,
 * terminated, exactly when they fit, and -ENAMETOOLONG with an empty
 * string otherwise.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/paths.c"

#define LEN_MAX	1

static char *any_string(size_t *len)
{
	char *s;

	__CPROVER_assume(*len <= LEN_MAX);
	s = any_bytes(*len + 1);
	__CPROVER_assume(!s[*len] && strnlen(s, *len) == *len);
	return s;
}

static size_t holds(const char *out, size_t off, const char *part,
		    size_t len)
{
	__CPROVER_assert(!memcmp(out + off, part, len), "the part, as given");
	return off + len;
}

void harness(void)
{
	size_t ln, la, lb, lp, off, need, cap = LEN;
	char bpffs[2 * LEN_MAX + 1];
	char *name, *a, *b, *out;
	__u32 parts;
	int ret;

	name = any_string(&ln);
	a = any_string(&la);
	b = any_string(&lb);
	__CPROVER_assume(parts <= 2);
	out = any_bytes(cap);
	if (parts == 0)
		ret = upatch_pin_path(out, cap, name, NULL);
	else if (parts == 1)
		ret = upatch_pin_path(out, cap, name, a, NULL);
	else
		ret = upatch_pin_path(out, cap, name, a, b, NULL);
	__CPROVER_assert(!upatch_bpffs_name(bpffs, sizeof(bpffs), name),
			 "a short name has a pin name");
	lp = strlen(bpffs);
	need = sizeof(BPFFS_UPATCHES_DIR) + lp;
	if (parts >= 1)
		need += 1 + la;
	if (parts == 2)
		need += 1 + lb;
	__CPROVER_assert(!ret || ret == -ENAMETOOLONG, "0 or -ENAMETOOLONG");
	__CPROVER_assert(!ret == (need < cap), "exactly when it fits");
	if (ret) {
		__CPROVER_assert(!cap || !out[0], "empty on refusal");
		return;
	}
	off = holds(out, 0, BPFFS_UPATCHES_DIR,
		    sizeof(BPFFS_UPATCHES_DIR) - 1);
	__CPROVER_assert(out[off++] == '/', "a slash before the pin name");
	off = holds(out, off, bpffs, lp);
	if (parts >= 1) {
		__CPROVER_assert(out[off++] == '/', "a slash before a part");
		off = holds(out, off, a, la);
	}
	if (parts == 2) {
		__CPROVER_assert(out[off++] == '/', "a slash before a part");
		off = holds(out, off, b, lb);
	}
	__CPROVER_assert(!out[off], "terminated");
}
