// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The bpm source and tree config lines util/bpm_source_config.c reads, for
 * every line of up to LINE_MAX bytes: a setting is written only for its own
 * key and holds the text after the first '=', a source one without the
 * blanks before it and cut at a line break, a tree one without the blanks
 * around it or the quotes that enclose it; one that does not fit is refused.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_source_config.c"
#include "../../../util/string.c"

/* "index_repository=" and a value of up to 5 bytes, one past OUT. */
#define LINE_MAX	22
#define OUT		4

static bool blank(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

/* Where a setting's text lies in the line: from, and up to before to. */
struct span {
	size_t	from, to;
};

/* After the first '=', without the blanks before it, up to CR or LF. */
static struct span source_value(const char *line, size_t eq)
{
	struct span v = { eq + 1, 0 };

	while (blank(line[v.from]))
		v.from++;
	for (v.to = v.from; line[v.to] && line[v.to] != '\r' &&
	     line[v.to] != '\n'; v.to++)
		;
	return v;
}

/* After the first '=', without the blanks around it. */
static struct span tree_value(const char *line, size_t eq)
{
	struct span v = { eq + 1, strlen(line) };

	while (v.from < v.to && blank(line[v.from]))
		v.from++;
	while (v.to > v.from && blank(line[v.to - 1]))
		v.to--;
	return v;
}

/* Written for its key alone, and then the text of the span, terminated. */
static bool setting(const char *out, const char *was, bool mine,
		    const char *line, struct span v)
{
	size_t n = v.to - v.from;

	if (!mine)
		return !memcmp(out, was, OUT);
	return n < OUT && !memcmp(out, line + v.from, n) && !out[n];
}

/* The key a parsed line leaves at its start, the blanks around it gone. */
static bool key_is(const char *line, const char *eq, const char *name)
{
	while (blank(*line))
		line++;
	return eq && !strcmp(line, name);
}

static char *any_line(char *was)
{
	char *line = any_bytes(LINE_MAX + 1);

	__CPROVER_assume(!line[LINE_MAX]);
	memcpy(was, line, LINE_MAX + 1);
	return line;
}

static void source_line(void)
{
	char endpoint[OUT], repo[OUT], key[OUT], e[OUT], r[OUT], k[OUT];
	char was[LINE_MAX + 1], *line = any_line(was);
	char *eq = strchr(line, '=');
	bool is_e, is_r, is_k;
	struct span v;
	int ret;

	memcpy(e, endpoint, OUT);
	memcpy(r, repo, OUT);
	memcpy(k, key, OUT);
	ret = bpm_parse_source_line(line, endpoint, OUT, repo, OUT, key, OUT);
	is_e = key_is(line, eq, "endpoint");
	is_r = key_is(line, eq, "index_repository");
	is_k = key_is(line, eq, "key_file");
	if (!eq) {
		__CPROVER_assert(!ret && !memcmp(endpoint, e, OUT) &&
				 !memcmp(repo, r, OUT) && !memcmp(key, k, OUT),
				 "a line without '=' sets nothing");
		return;
	}
	v = source_value(was, (size_t)(eq - line));
	__CPROVER_assert(ret == ((is_e || is_r || is_k) &&
				 v.to - v.from >= OUT ? -E2BIG : 0),
			 "refused exactly when the value does not fit");
	if (ret)
		return;
	__CPROVER_assert(setting(endpoint, e, is_e, was, v) &&
			 setting(repo, r, is_r, was, v) &&
			 setting(key, k, is_k, was, v),
			 "a setting for its key, the text after '=' up to a "
			 "line break, without blanks before it");
}

static void tree_line(void)
{
	char endpoint[OUT], reference[OUT], e[OUT], r[OUT];
	char was[LINE_MAX + 1], *line = any_line(was);
	char *eq = strchr(line, '=');
	bool is_e, is_r, quoted;
	struct span v;
	int ret;

	memcpy(e, endpoint, OUT);
	memcpy(r, reference, OUT);
	ret = bpm_parse_tree_line(line, endpoint, OUT, reference, OUT);
	is_e = key_is(line, eq, "endpoint");
	is_r = key_is(line, eq, "reference");
	if (!eq) {
		__CPROVER_assert(!ret && !memcmp(endpoint, e, OUT) &&
				 !memcmp(reference, r, OUT),
				 "a line without '=' sets nothing");
		return;
	}
	v = tree_value(was, (size_t)(eq - line));
	quoted = v.to > v.from && was[v.from] == '"';
	if (quoted && (v.to - v.from < 2 || was[v.to - 1] != '"')) {
		__CPROVER_assert(ret == -EINVAL, "an open quote refused");
		return;
	}
	if (quoted) {
		v.from++;
		v.to--;
	}
	__CPROVER_assert(ret == ((is_e || is_r) && v.to - v.from >= OUT ?
				 -E2BIG : 0),
			 "refused exactly when the value does not fit");
	if (ret)
		return;
	__CPROVER_assert(setting(endpoint, e, is_e, was, v) &&
			 setting(reference, r, is_r, was, v),
			 "a setting for its key, the text after '=' without "
			 "the blanks around it or its quotes");
}

void harness(void)
{
	source_line();
	tree_line();
}
