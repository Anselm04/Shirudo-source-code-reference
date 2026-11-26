// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The number parsers of util/string.c on every string of up to LEN_MAX
 * bytes: nothing past the string is read, what is no number is refused,
 * a result keeps within its bounds and a refusal leaves it unwritten.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

#define LEN_MAX	22	/* past the 20 digits of the largest __u64 */
#define UNSET	0x5a5a5a5a5a5a5a5aULL

static bool is_digit(char c, bool hex)
{
	return (c >= '0' && c <= '9') ||
	       (hex && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')));
}

static bool all_digits(const char *s, size_t len, bool hex)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (!is_digit(s[i], hex))
			return false;
	return true;
}

static void unsigned_number(bool hex)
{
	__u64 max, out = UNSET;
	size_t len;
	char *s;
	int ret;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_bytes(len);
	ret = hex ? parse_x64(s, len, max, &out) :
		    parse_u64(s, len, max, &out);
	__CPROVER_assert(!ret || ret == -EINVAL || ret == -ERANGE,
			 "only 0, -EINVAL or -ERANGE");
	__CPROVER_assert((ret == -EINVAL) == (!len || !all_digits(s, len, hex)),
			 "-EINVAL for what is empty or holds a non-digit");
	__CPROVER_assert(ret || out <= max, "a number within its bound");
	__CPROVER_assert(!ret || out == UNSET, "nothing written on refusal");
}

static void signed_number(void)
{
	__s64 min, max, out = (__s64)UNSET;
	bool neg, number;
	size_t len;
	char *s;
	int ret;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_bytes(len);
	ret = parse_s64(s, len, min, max, &out);
	neg = len && s[0] == '-';
	number = len > neg && all_digits(s + neg, len - neg, false);
	__CPROVER_assert(!ret || ret == -EINVAL || ret == -ERANGE,
			 "only 0, -EINVAL or -ERANGE");
	__CPROVER_assert((ret == -EINVAL) == !number,
			 "-EINVAL for what is no optionally signed number");
	__CPROVER_assert(ret || (out >= min && out <= max),
			 "a number within its bounds");
	__CPROVER_assert(ret || (neg ? out <= 0 : out >= 0),
			 "the sign the string spells");
	__CPROVER_assert(!ret || out == (__s64)UNSET,
			 "nothing written on refusal");
}

static void leading_digits(void)
{
	size_t len, n;
	char *s;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_bytes(len);
	n = digits(s, len);
	__CPROVER_assert(n <= len && all_digits(s, n, false),
			 "a run of digits within the string");
	__CPROVER_assert(n == len || !is_digit(s[n], false),
			 "the whole run");
}

void harness(void)
{
	unsigned_number(false);
	unsigned_number(true);
	signed_number();
	leading_digits();
}
