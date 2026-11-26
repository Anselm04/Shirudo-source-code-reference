// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The upatch names util/upatch.c takes from outside, for every name of up
 * to LEN_MAX bytes and every one of LONG_LEN bytes that ends in letters:
 * upatch_name_valid() accepts exactly [A-Za-z0-9._-]+ not starting with a
 * dot whose pin directory, each dot two bytes, fits NAME_MAX, so no path
 * separator, "." or "..",
 * upatch_select() exactly the archive names, something then ".upatch",
 * and upatch_prog_name() gives the loader program a zero-padded name the
 * kernel takes, the header's with every other byte made '_'.
 */

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/upatch.c"

#define LEN_MAX	24

static bool name_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static void name_valid(void)
{
	size_t n, i, pin = 0;
	bool valid, chars = true;
	char *name;

	__CPROVER_assume(n <= LEN_MAX);
	name = any_bytes(n + 1);
	__CPROVER_assume(!name[n] && strnlen(name, n) == n);
	valid = upatch_name_valid(name);
	for (i = 0; i < n; i++) {
		chars &= name_char(name[i]);
		pin += name[i] == '.' ? 2 : 1;
	}
	__CPROVER_assert(valid == (n > 0 && name[0] != '.' && chars &&
				   pin <= NAME_MAX),
			 "exactly the names of the pattern whose pin fits");
	for (i = 0; i < n; i++)
		__CPROVER_assert(!valid || name[i] != '/', "no separator");
	__CPROVER_assert(!upatch_name_valid(NULL), "no name is invalid");
}

/*
 * A name of LONG_LEN bytes, any LONG_SYMBOLIC of them first and letters
 * after, whose dots take its pin directory across NAME_MAX.
 */
#define LONG_LEN	250
#define LONG_SYMBOLIC	8

static void long_name_valid(void)
{
	char *name = any_bytes(LONG_LEN + 1);
	size_t i, pin = LONG_LEN;
	bool chars = true;

	for (i = 0; i < LONG_SYMBOLIC; i++) {
		__CPROVER_assume(name[i]);
		chars = chars && name_char(name[i]);
		pin += name[i] == '.';
	}
	for (i = LONG_SYMBOLIC; i < LONG_LEN; i++)
		name[i] = 'a';
	name[LONG_LEN] = '\0';
	__CPROVER_assert(upatch_name_valid(name) ==
			 (name[0] != '.' && chars && pin <= NAME_MAX),
			 "a long name valid exactly while its pin fits");
}

static void archive_name(void)
{
	static const char suffix[] = ".upatch";
	const size_t suffix_len = sizeof(suffix) - 1;
	struct dirent e;
	size_t n;
	int ret;

	__CPROVER_assume(n <= LEN_MAX + suffix_len &&
			 !e.d_name[n] && strnlen(e.d_name, n) == n);
	ret = upatch_select(&e);
	__CPROVER_assert(ret == (n > suffix_len &&
				 !memcmp(e.d_name + n - suffix_len, suffix,
					 suffix_len)),
			 "exactly a name before .upatch");
}

static bool prog_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_' || c == '.';
}

static void prog_name(void)
{
	size_t n, len = 0, i;
	struct upatch u;
	char out[16];

	__CPROVER_assume(n <= LEN_MAX && !u.hdr.name[n]);
	while (u.hdr.name[len])
		len++;
	upatch_prog_name(&u, out, sizeof(out));
	for (i = 0; i < sizeof(out); i++) {
		char c = u.hdr.name[i];

		if (i < len && i < sizeof(out) - 1)
			__CPROVER_assert(out[i] == (prog_char(c) ? c : '_'),
					 "the header's byte, or '_'");
		else
			__CPROVER_assert(!out[i], "zero-padded");
	}
}

void harness(void)
{
	prog_name();
	name_valid();
	long_name_valid();
	archive_name();
}
