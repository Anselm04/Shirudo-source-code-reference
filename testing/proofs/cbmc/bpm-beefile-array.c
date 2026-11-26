// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * An array value of a Beefile, on every value of up to VALUE_MAX bytes:
 * build_parse_string_array() of tools/shirudo-build/bpm-build.c takes one
 * string or more up to its limit, each terminated in its row, between
 * brackets, and counts none of an array it refuses.
 * bpm-beefile-array-long.c includes this file for an element as long as
 * the parser's copy of it.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../tools/shirudo-build/bpm-build.c"

#define VALUE_MAX	10
#define ROWS		2

static bool blank(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

#ifdef BEEFILE_ARRAY_LONG
/* The copy build_parse_string_array() takes of an element. */
#define ITEM_COPY	1024

/*
 * One element of LEN bytes, its quotes included, of a constant byte:
 * refused, as too long for the copy or for its row, with nothing counted.
 */
void harness(void)
{
	char out[1][TREE_STRING_MAX], v[LEN + 3];
	const size_t len = LEN;
	size_t i;
	int n = 0;

	v[0] = '[';
	v[1] = '"';
	for (i = 2; i < LEN; i++)
		v[i] = 'x';
	v[LEN] = '"';
	v[LEN + 1] = ']';
	v[LEN + 2] = '\0';
	__CPROVER_assert(build_parse_string_array(v, out, 1, &n) ==
			 (len >= ITEM_COPY ? -ENAMETOOLONG : -EINVAL) && !n,
			 "an element too long for its copy or its row refused");
}
#else
void harness(void)
{
	char out[ROWS][TREE_STRING_MAX], was_byte;
	size_t first = 0, last, j, k;
	int n, was, max, ret;
	char *v;

	v = any_bytes(VALUE_MAX + 1);
	v[VALUE_MAX] = '\0';
	/* Every caller passes a limit of 16, the rows of its table. */
	__CPROVER_assume(max >= 1 && max <= ROWS && j < TREE_STRING_MAX);
	was = n;
	was_byte = out[ROWS - 1][j];
	ret = build_parse_string_array(v, out, max, &n);
	__CPROVER_assert(max == ROWS || out[ROWS - 1][j] == was_byte,
			 "no row past the limit written");
	if (ret) {
		__CPROVER_assert(n == was, "a refused array is not counted");
		return;
	}
	__CPROVER_assert(n >= 1 && n <= max, "one string or more, to the limit");
	__CPROVER_assume(k < (size_t)n);
	__CPROVER_assert(strnlen(out[k], VALUE_MAX + 1) <= VALUE_MAX,
			 "each string terminated");
	last = strnlen(v, VALUE_MAX);
	while (first < last && blank(v[first]))
		first++;
	while (last > first && blank(v[last - 1]))
		last--;
	__CPROVER_assert(last - first >= 2 && v[first] == '[' &&
			 v[last - 1] == ']', "between brackets");
}
#endif
