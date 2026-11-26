// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The typed fields of util/json.c on every value of LEN bytes: an integer
 * field takes an integer of ECMA-404, a string field a string that fits,
 * a boolean field true or false, null leaves a field unseen, and anything
 * else is refused.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

#define STR_CAP	3

static bool in(__s64 c, __s64 lo, __s64 hi)
{
	return c >= lo && c <= hi;
}

static size_t digits_end(const __u8 *t, size_t n, size_t i)
{
	while (i < n && in(t[i], '0', '9'))
		i++;
	return i;
}

/* Past the integer part of ECMA-404, section 8, at t[i]; 0 if none. */
static size_t integer_end(const __u8 *t, size_t n, size_t i)
{
	if (i < n && t[i] == '-')
		i++;
	if (i < n && t[i] == '0')
		return i + 1;
	if (i < n && in(t[i], '1', '9'))
		return digits_end(t, n, i);
	return 0;
}

static bool word(const __u8 *t, size_t n, size_t i, const char *w)
{
	size_t k = strlen(w);

	return n - i >= k && !memcmp(t + i, w, k);
}

static __s64 decimal(const __u8 *t, size_t i, size_t end)
{
	bool neg = t[i] == '-';
	__s64 v = 0;

	for (i += neg; i < end; i++)
		v = v * 10 + t[i] - '0';
	return neg ? -v : v;
}

static void integer(const __u8 *t, size_t i)
{
	struct pctx c = { .p = (const char *)t, .end = (const char *)t + LEN };
	struct json_field f = { "k", JSON_T_INT, NULL, 0, 0, NULL, 0 };
	size_t end = integer_end(t, LEN, i);
	__s64 num = 0;
	int ret;

	f.dst = &num;
	ret = parse_value(&c, &f);
	if (word(t, LEN, i, "null")) {
		__CPROVER_assert(!ret && !f.seen, "null leaves it unseen");
		return;
	}
	if (!end || (end < LEN && (t[end] == '.' || t[end] == 'e' ||
				   t[end] == 'E'))) {
		__CPROVER_assert(ret == -EINVAL, "no integer refused");
		return;
	}
	__CPROVER_assert(!ret && f.seen && num == decimal(t, i, end) &&
			 c.p == (const char *)t + end, "an integer taken");
}

static void string(const __u8 *t, size_t i)
{
	struct pctx c = { .p = (const char *)t, .end = (const char *)t + LEN };
	struct json_field f = { "k", JSON_T_STRING, NULL, STR_CAP, 0, NULL,
				0 };
	char str[STR_CAP];
	int ret;

	f.dst = str;
	ret = parse_value(&c, &f);
	if (word(t, LEN, i, "null")) {
		__CPROVER_assert(!ret && !f.seen, "null leaves it unseen");
		return;
	}
	if (i == LEN || t[i] != '"') {
		__CPROVER_assert(ret == -EINVAL, "no string refused");
		return;
	}
	__CPROVER_assert(!ret == f.seen && (!ret || ret == -EINVAL ||
					    ret == -ENOSPC),
			 "a string taken, or refused");
	__CPROVER_assert(ret || strnlen(str, STR_CAP) < STR_CAP,
			 "a string that fits");
}

static void boolean(const __u8 *t, size_t i)
{
	struct pctx c = { .p = (const char *)t, .end = (const char *)t + LEN };
	struct json_field f = { "k", JSON_T_BOOL, NULL, 0, 0, NULL, 0 };
	bool yes = word(t, LEN, i, "true"), no = word(t, LEN, i, "false");
	int flag = -1, ret;

	f.dst = &flag;
	ret = parse_value(&c, &f);
	if (word(t, LEN, i, "null")) {
		__CPROVER_assert(!ret && !f.seen, "null leaves it unseen");
		return;
	}
	__CPROVER_assert(!ret == (yes || no) && (!ret || ret == -EINVAL),
			 "true and false taken alone");
	__CPROVER_assert(ret || (f.seen && flag == yes), "as 1 and 0");
}

void harness(void)
{
	const __u8 *t;
	size_t i = 0;

	t = any_bytes(LEN);
	while (i < LEN && (t[i] == ' ' || t[i] == '\t' || t[i] == '\n' ||
			   t[i] == '\r'))
		i++;
	integer(t, i);
	string(t, i);
	boolean(t, i);
}
