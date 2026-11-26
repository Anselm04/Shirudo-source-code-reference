// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * name_has_suffix() of util/string.c on every name of up to LEN_MAX bytes
 * and every suffix of up to SUFFIX_MAX: true exactly when the name is a
 * stem of at least one byte and then the suffix, reading only the name's
 * len bytes.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define LEN_MAX		6
#define SUFFIX_MAX	3

void harness(void)
{
	bool ret, differ = false;
	char *name, *suffix;
	size_t len, n, i;

	__CPROVER_assume(len <= LEN_MAX && n <= SUFFIX_MAX);
	name = any_bytes(len);
	suffix = any_bytes(n + 1);
	__CPROVER_assume(!suffix[n] && strnlen(suffix, n) == n);
	ret = name_has_suffix(name, len, suffix);
	if (len <= n) {
		__CPROVER_assert(!ret, "never without a stem of a byte or more");
		return;
	}
	for (i = 0; i < n; i++)
		if (name[len - n + i] != suffix[i])
			differ = true;
	__CPROVER_assert(ret == !differ, "the name's last bytes are the suffix");
}
