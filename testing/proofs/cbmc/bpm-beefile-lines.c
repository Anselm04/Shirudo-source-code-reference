// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A line of a Beefile as tools/shirudo-build/bpm-build.c cuts it up, on
 * every line of LEN bytes: a comment is cut at a '#' and never inside a
 * string the reader takes, trimming drops the blanks at both ends alone,
 * and a table or key name is bare parts apart by single dots.
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

#include "proof.h"
#include "../../../util/string.c"
#include "../../../tools/shirudo-build/bpm-build.c"

/* What follows the '#' behind a string, any bytes. */
#define TAIL		2

static bool blank(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

static bool bare(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z') || c == '_' || c == '-';
}

/* Any string of len bytes, with room for more behind it. */
static char *string(size_t len, size_t room)
{
	char *s = any_bytes(room + 1);

	__CPROVER_assume(strnlen(s, len) == len);
	s[len] = '\0';
	return s;
}

static void comment_cut(void)
{
	char *line = string(LEN, LEN), was[LEN + 1];
	bool quotes = false;
	size_t i, n, hash, at;

	for (i = 0; i <= LEN; i++) {
		was[i] = line[i];
		quotes |= line[i] == '"' || line[i] == '\'';
	}
	for (hash = 0; hash < LEN && was[hash] != '#'; hash++)
		;
	build_strip_comment(line);
	n = strnlen(line, LEN);
	__CPROVER_assume(at <= LEN);
	__CPROVER_assert(at == n || line[at] == was[at],
			 "no byte changed but the one that ends the line");
	__CPROVER_assert(n == LEN || was[n] == '#', "cut at a '#' or not at all");
	__CPROVER_assert(quotes || n == hash,
			 "at the first one of a line without a quote");
}

/* key = "a # b" # comment: the string stays whole and the comment goes. */
static void string_kept(void)
{
	char *line = string(LEN, LEN + 1 + TAIL), out[LEN + 1], was[LEN];
	size_t i;

	if (build_parse_string(line, out, sizeof(out)))
		return;
	for (i = 0; i < LEN; i++)
		was[i] = line[i];
	line[LEN] = '#';
	__CPROVER_assume(strnlen(line + LEN + 1, TAIL) == TAIL);
	line[LEN + 1 + TAIL] = '\0';
	build_strip_comment(line);
	__CPROVER_assert(strnlen(line, LEN + 1) == LEN &&
			 !memcmp(line, was, LEN),
			 "a string the reader takes kept whole, its comment cut");
}

static void trimmed(void)
{
	char *line = string(LEN, LEN), was[LEN + 1];
	size_t i, from, n, at;
	char *s;

	for (i = 0; i <= LEN; i++)
		was[i] = line[i];
	s = build_trim(line);
	__CPROVER_assert(s >= line && s <= line + LEN, "inside the line");
	from = (size_t)(s - line);
	n = strnlen(s, LEN - from);
	__CPROVER_assert(!n || (!blank(s[0]) && !blank(s[n - 1])),
			 "no blank at either end");
	__CPROVER_assume(at < LEN);
	__CPROVER_assert(at >= from && at < from + n ? s[at - from] == was[at] :
			 blank(was[at]), "nothing but blanks dropped");
}

static void named(void)
{
	char *key = string(LEN, LEN);
	bool dots, parts = LEN > 0;
	size_t i;

	for (i = 0; i < LEN; i++)
		parts &= bare(key[i]) ||
			 (dots && key[i] == '.' && i && i + 1 < LEN &&
			  key[i - 1] != '.' && key[i + 1] != '.');
	__CPROVER_assert(build_bare_key(key, dots) == parts,
			 "bare parts, apart by single dots where dots may be");
}

void harness(void)
{
	comment_cut();
	string_kept();
	trimmed();
	named();
}
