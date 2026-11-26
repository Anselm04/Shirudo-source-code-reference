// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_tar_octal() of util/bpm_package.c on every field of LEN bytes, the
 * size and checksum fields of a ustar header: it reads exactly octal
 * digits with nothing but blanks or NULs around them, and the value it
 * returns reads back as those digits.
 */

#include "proof.h"
#include "../../../util/bpm_package.c"

static bool blank(char c)
{
	return c == ' ' || c == '\0';
}

static bool octal(char c)
{
	return c >= '0' && c <= '7';
}

/* The one run of digits in p, from first to last, blanks around it. */
static bool octal_shape(const char *p, size_t n, size_t *first, size_t *last)
{
	bool in_run = false, after = false;
	size_t i;

	*first = n;
	*last = n;
	for (i = 0; i < n; i++) {
		if (octal(p[i]) && !after) {
			if (!in_run)
				*first = i;
			in_run = true;
		} else if (blank(p[i])) {
			if (in_run && !after)
				*last = i;
			after = in_run;
		} else {
			return false;
		}
	}
	return in_run;
}

void harness(void)
{
	size_t first, last, i;
	__u64 v, was;
	bool shaped;
	char *p;
	int ret;

	p = any_bytes(LEN);
	v = was;
	ret = bpm_tar_octal(p, LEN, &v);
	shaped = octal_shape(p, LEN, &first, &last);
	__CPROVER_assert(!ret == shaped, "exactly the octal fields are read");
	if (ret) {
		__CPROVER_assert(v == was, "a refusal leaves the value alone");
		return;
	}
	for (i = first; i < last; i++)
		__CPROVER_assert(((v >> (3 * (last - 1 - i))) & 7) ==
				 (__u64)(p[i] - '0'),
				 "each digit read back from the value");
	__CPROVER_assert(!(v >> (3 * (last - first))),
			 "no bits beyond the digits");
}
