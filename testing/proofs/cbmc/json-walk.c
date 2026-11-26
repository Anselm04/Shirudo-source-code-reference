// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * json_walk() of util/json.c on every input of LEN bytes: it takes exactly
 * one value of ECMA-404 under json.h's restrictions, as a pushdown
 * automaton of the grammar decides, reports containers in pairs, strings
 * terminated and numbers as their whole text.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

enum want { VALUE, FIRST_KEY, KEY, COLON, FIRST_VALUE, NEXT, END };

static bool in(__s64 c, __s64 lo, __s64 hi)
{
	return c >= lo && c <= hi;
}

/* Table 3-7 of the Unicode Standard, row by row. */
static size_t table_width(const __u8 *s, size_t n)
{
	if (n >= 1 && s[0] <= 0x7f)
		return 1;
	if (n >= 2 && in(s[0], 0xc2, 0xdf) && in(s[1], 0x80, 0xbf))
		return 2;
	if (n >= 3 && in(s[2], 0x80, 0xbf) &&
	    ((s[0] == 0xe0 && in(s[1], 0xa0, 0xbf)) ||
	     (in(s[0], 0xe1, 0xec) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xed && in(s[1], 0x80, 0x9f)) ||
	     (in(s[0], 0xee, 0xef) && in(s[1], 0x80, 0xbf))))
		return 3;
	if (n >= 4 && in(s[2], 0x80, 0xbf) && in(s[3], 0x80, 0xbf) &&
	    ((s[0] == 0xf0 && in(s[1], 0x90, 0xbf)) ||
	     (in(s[0], 0xf1, 0xf3) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xf4 && in(s[1], 0x80, 0x8f))))
		return 4;
	return 0;
}

static bool hex_digit(__u8 c)
{
	return in(c, '0', '9') || in(c, 'a', 'f') || in(c, 'A', 'F');
}

/* The code unit of \uXXXX at t[i], or -1. */
static int code_unit(const __u8 *t, size_t n, size_t i)
{
	int cu = 0, j;

	if (i + 6 > n || t[i] != '\\' || t[i + 1] != 'u')
		return -1;
	for (j = 2; j < 6; j++) {
		if (!hex_digit(t[i + j]))
			return -1;
		cu = cu * 16 + (t[i + j] <= '9' ? t[i + j] - '0' :
				(t[i + j] | 0x20) - 'a' + 10);
	}
	return cu;
}

/*
 * Past the string of ECMA-404, section 9, at t[i], with no \u0000, no lone
 * surrogate escape and nothing but well-formed UTF-8; 0 if none.
 */
static size_t string_end(const __u8 *t, size_t n, size_t i)
{
	static const char escapes[] = "\"\\/bfnrt";
	size_t w;
	int cu;

	if (t[i++] != '"')
		return 0;
	while (i < n && t[i] != '"') {
		if (t[i] < 0x20)
			return 0;
		if (t[i] != '\\') {
			w = table_width(t + i, n - i);
			if (!w)
				return 0;
			i += w;
			continue;
		}
		if (i + 1 < n &&
		    memchr(escapes, t[i + 1], sizeof(escapes) - 1)) {
			i += 2;
			continue;
		}
		cu = code_unit(t, n, i);
		if (cu <= 0 || in(cu, 0xdc00, 0xdfff))
			return 0;
		i += 6;
		if (!in(cu, 0xd800, 0xdbff))
			continue;
		if (!in(code_unit(t, n, i), 0xdc00, 0xdfff))
			return 0;
		i += 6;
	}
	return i < n ? i + 1 : 0;
}

static size_t digits_end(const __u8 *t, size_t n, size_t i)
{
	while (i < n && in(t[i], '0', '9'))
		i++;
	return i;
}

/* Past the number of ECMA-404, section 8, at t[i]; 0 if none. */
static size_t number_end(const __u8 *t, size_t n, size_t i)
{
	size_t j;

	if (i < n && t[i] == '-')
		i++;
	if (i < n && t[i] == '0')
		i++;
	else if (i < n && in(t[i], '1', '9'))
		i = digits_end(t, n, i);
	else
		return 0;
	if (i < n && t[i] == '.') {
		j = digits_end(t, n, i + 1);
		if (j == i + 1)
			return 0;
		i = j;
	}
	if (i < n && (t[i] == 'e' || t[i] == 'E')) {
		i += i + 1 < n && (t[i + 1] == '+' || t[i + 1] == '-');
		j = digits_end(t, n, i + 1);
		if (j == i + 1)
			return 0;
		i = j;
	}
	return i;
}

static size_t literal_end(const __u8 *t, size_t n, size_t i)
{
	static const char *const words[] = { "true", "false", "null" };
	size_t w, k;

	for (w = 0; w < ARRAY_SIZE(words); w++) {
		k = strlen(words[w]);
		if (n - i >= k && !memcmp(t + i, words[w], k))
			return i + k;
	}
	return 0;
}

static bool space(__u8 c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/*
 * The grammar of ECMA-404 as a pushdown automaton: 0 for one value with
 * white space around it, -E2BIG for a container past JSON_MAX_DEPTH and
 * -EINVAL for anything else.
 */
static int json_text(const __u8 *t, size_t n)
{
	bool array[JSON_MAX_DEPTH];
	size_t i = 0, depth = 0;
	enum want want = VALUE;
	__u8 c;

	for (;;) {
		while (i < n && space(t[i]))
			i++;
		if (i == n)
			return want == END ? 0 : -EINVAL;
		c = t[i];
		if (want == END || (want == COLON && c != ':'))
			return -EINVAL;
		if (want == COLON) {
			want = VALUE;
			i++;
			continue;
		}
		if ((want == NEXT && c == ',') || (want == FIRST_KEY && c == '}') ||
		    (want == FIRST_VALUE && c == ']') ||
		    (want == NEXT && c == (array[depth - 1] ? ']' : '}'))) {
			if (c == ',')
				want = array[depth - 1] ? VALUE : KEY;
			else
				want = --depth ? NEXT : END;
			i++;
			continue;
		}
		if (want == NEXT)
			return -EINVAL;
		if (want == FIRST_KEY || want == KEY) {
			i = string_end(t, n, i);
			if (!i)
				return -EINVAL;
			want = COLON;
			continue;
		}
		if (c == '{' || c == '[') {
			if (depth == JSON_MAX_DEPTH)
				return -E2BIG;
			array[depth++] = c == '[';
			want = c == '[' ? FIRST_VALUE : FIRST_KEY;
			i++;
			continue;
		}
		if (c == '"')
			i = string_end(t, n, i);
		else if (c == '-' || in(c, '0', '9'))
			i = number_end(t, n, i);
		else
			i = literal_end(t, n, i);
		if (!i)
			return -EINVAL;
		want = depth ? NEXT : END;
	}
}

struct walk {
	const char	*data;
	bool		array[LEN + 1];
	size_t		depth;
	size_t		calls;
};

static int called(struct walk *w)
{
	w->calls++;
	return 0;
}

static int on_open(void *ctx, bool array)
{
	struct walk *w = ctx;

	__CPROVER_assert(w->depth < JSON_MAX_DEPTH, "within the depth");
	w->array[w->depth++] = array;
	return called(w);
}

static int on_close(void *ctx, bool array)
{
	struct walk *w = ctx;

	__CPROVER_assert(w->depth && w->array[w->depth - 1] == array,
			 "the container last opened closed");
	w->depth--;
	return called(w);
}

static int on_string(void *ctx, const char *s)
{
	__CPROVER_assert(strnlen(s, LEN + 1) <= LEN, "a terminated string");
	return called(ctx);
}

static int on_number(void *ctx, const char *text, size_t len, bool integer)
{
	struct walk *w = ctx;
	size_t at = text - w->data;

	__CPROVER_assert(text >= w->data && at + len <= LEN,
			 "a number inside the input");
	__CPROVER_assert(len && number_end((const __u8 *)w->data, LEN, at) ==
			 at + len, "its whole text");
	__CPROVER_assert(integer == !(memchr(text, '.', len) ||
				      memchr(text, 'e', len) ||
				      memchr(text, 'E', len)),
			 "an integer without fraction and exponent");
	return called(w);
}

static int on_literal(void *ctx, int value)
{
	__CPROVER_assert(value >= -1 && value <= 1, "true, false or null");
	return called(ctx);
}

static const struct json_visitor visitor = {
	.open = on_open,
	.close = on_close,
	.key = on_string,
	.string = on_string,
	.number = on_number,
	.literal = on_literal,
};

void harness(void)
{
	struct walk w = {};
	char *data;
	int ret;

	data = any_bytes(LEN);
	w.data = data;
	ret = json_walk(data, LEN, &visitor, &w);
	__CPROVER_assert(ret == json_text((const __u8 *)data, LEN),
			 "exactly one value of ECMA-404 taken");
	__CPROVER_assert(ret || !w.depth, "every container closed");
	__CPROVER_assert(json_walk(data, LEN, NULL, NULL) == -EINVAL,
			 "a visitor needed");
}
