// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A string value of a Beefile, on every value of LEN bytes:
 * build_parse_string() of tools/shirudo-build/bpm-build.c takes exactly a
 * quoted string that fits its buffer, decoded as the Beefile reference
 * says, and writes nothing past the buffer.
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

#define OUT_MAX		(LEN + 1)

static bool blank(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

/*
 * A string as the Beefile reference has it, between the blanks around
 * it: a quote, text and the same quote, with \n, \r, \t, \\ and \" in a
 * "..." string and no escape in a '...' one. The length of the text
 * decoded into d, or -1.
 */
static int quoted(const char *v, char *d)
{
	static const char escapes[] = "nrt\\\"";
	size_t from = 0, to = LEN, i;
	int n = 0;
	char c;

	while (from < LEN && blank(v[from]))
		from++;
	while (to > from && blank(v[to - 1]))
		to--;
	if (to - from < 2 || (v[from] != '"' && v[from] != '\'') ||
	    v[to - 1] != v[from])
		return -1;
	for (i = from + 1; i < to - 1; i++) {
		c = v[i];
		if (c == v[from])
			return -1;
		if (c == '\\' && v[from] == '"') {
			c = v[++i];
			if (i == to - 1 ||
			    !memchr(escapes, c, sizeof(escapes) - 1))
				return -1;
			c = c == 'n' ? '\n' : c == 'r' ? '\r' : c == 't' ? '\t' : c;
		}
		d[n++] = c;
	}
	return n;
}

static void string_value(const char *v)
{
	char out[OUT_MAX], text[LEN + 1], was;
	size_t cap, i;
	int n, ret;

	/* Every caller passes the size of an array, 16 bytes or more. */
	__CPROVER_assume(cap >= 1 && cap <= OUT_MAX && i < OUT_MAX);
	was = out[i];
	ret = build_parse_string(v, out, cap);
	n = quoted(v, text);
	__CPROVER_assert(!ret == (n >= 0 && (size_t)n < cap),
			 "exactly a quoted string that fits");
	__CPROVER_assert(i < cap || out[i] == was, "nothing past its buffer");
	if (ret) {
		__CPROVER_assert(ret == -EINVAL || ret == -ENAMETOOLONG,
				 "refused as malformed or too long");
		return;
	}
	__CPROVER_assert(n >= 0 && !out[n] && !memcmp(out, text, (size_t)n),
			 "the text between the quotes, decoded and terminated");
}

/* authors alone takes an array, which bpm build reads past. */
static void ignored_value(const char *v)
{
	char out[OUT_MAX];
	size_t first = 0;

	while (first < LEN && blank(v[first]))
		first++;
	if (build_parse_value(v, out, sizeof(out), true))
		return;
	__CPROVER_assert(quoted(v, out) >= 0 ||
			 (first < LEN && v[first] == '['),
			 "a string, or what starts as an array");
}

void harness(void)
{
	char *v = any_bytes(LEN + 1);

	__CPROVER_assume(strnlen(v, LEN) == LEN);
	v[LEN] = '\0';
	string_value(v);
	ignored_value(v);
}
