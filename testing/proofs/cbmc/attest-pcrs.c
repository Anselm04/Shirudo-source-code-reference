// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The --pcrs and <pcr>=<value> parsers of util/attest.c on every string
 * of up to LEN_MAX bytes: a list is accepted exactly when it is decimal
 * PCRs 0 to 23 apart by single commas, into the mask of those PCRs, and a
 * value exactly after a PCR and an equals sign.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/attest.c"

#define LEN_MAX	6

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

static void pcr_list(void)
{
	size_t len, i, digits_seen = 0;
	__u32 mask, want = 0;
	bool ok = true;
	__u64 v = 0;
	char *s;
	int ret;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_string(len);
	ret = attest_parse_pcrs(s, &mask);
	for (i = 0; i <= len; i++) {
		char c = i < len ? s[i] : ',';

		if (c == ',') {
			if (!digits_seen || v > 23)
				ok = false;
			else
				want |= 1U << v;
			digits_seen = 0;
			v = 0;
		} else if (c >= '0' && c <= '9') {
			digits_seen++;
			if (v <= 23)
				v = v * 10 + (__u64)(c - '0');
		} else {
			ok = false;
		}
	}
	__CPROVER_assert(!ret == ok, "PCRs 0 to 23 apart by single commas");
	__CPROVER_assert(ret || mask == want, "the mask of those PCRs");
}

static void pcr_value(void)
{
	const char *value;
	size_t len, n = 0;
	__u64 pcr, v = 0;
	char *s;
	int ret;

	__CPROVER_assume(len <= LEN_MAX);
	s = any_string(len);
	ret = attest_parse_pcr_value(s, &pcr, &value);
	while (n < len && s[n] >= '0' && s[n] <= '9') {
		if (v <= 23)
			v = v * 10 + (__u64)(s[n] - '0');
		n++;
	}
	__CPROVER_assert(!ret == (n && n < len && s[n] == '=' && v <= 23),
			 "a PCR to 23, then an equals sign");
	__CPROVER_assert(ret || (pcr == v && value == s + n + 1),
			 "the PCR, and the value after the sign");
}

void harness(void)
{
	pcr_list();
	pcr_value();
}
