// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The string helpers of util/bpm_oci.c, for every string of up to STR_MAX
 * bytes and buffer of up to OUT_MAX: bpm_trim() and bpm_copy_string() leave
 * the string, trimmed for the first, or what fits of it, terminated, and
 * bpm_digest_matches() takes "sha256:" and the hex in either case.
 */

#include "proof.h"
#include "../../../util/bpm_oci.c"

#define STR_MAX	6
#define OUT_MAX	4

static bool blank(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

static char *any_string(void)
{
	char *s = any_bytes(STR_MAX + 1);

	__CPROVER_assume(!s[STR_MAX]);
	return s;
}

static void trim(void)
{
	char *in = any_string(), *out = any_bytes(OUT_MAX);
	size_t size, len, first, last;
	int ret;

	__CPROVER_assume(size <= OUT_MAX);
	len = strlen(in);
	for (first = 0; first < len && blank(in[first]); first++)
		;
	for (last = len; last > first && blank(in[last - 1]); last--)
		;
	ret = bpm_trim(in, out, size);
	if (!size) {
		__CPROVER_assert(ret == -E2BIG, "no room is -E2BIG");
		return;
	}
	if (last - first < size) {
		__CPROVER_assert(!ret && !memcmp(out, in + first, last - first) &&
				 !out[last - first],
				 "the string without the blanks around it");
		return;
	}
	__CPROVER_assert(ret == -E2BIG &&
			 !memcmp(out, in + first, size - 1) && !out[size - 1],
			 "what fits of it, and -E2BIG");
}

static void copy_string(void)
{
	char *in = any_string(), *out = any_bytes(OUT_MAX);
	size_t size, n;

	__CPROVER_assume(size >= 1 && size <= OUT_MAX);
	bpm_copy_string(out, size, in);
	n = min(strlen(in), size - 1);
	__CPROVER_assert(!memcmp(out, in, n) && !out[n],
			 "what fits of the string, terminated");
}

static char lower(char c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static void digest_matches(void)
{
	char *want = any_bytes(STR_MAX + 8), *hex = any_string();
	bool same = str_has_prefix(want, "sha256:");
	size_t i;

	__CPROVER_assume(!want[STR_MAX + 7]);
	for (i = 0; same && (want[7 + i] || hex[i]); i++)
		same = lower(want[7 + i]) == lower(hex[i]);
	__CPROVER_assert(bpm_digest_matches(want, hex) == same,
			 "sha256: and the hex in either case");
	__CPROVER_assert(!bpm_digest_matches(NULL, hex), "no digest, no match");
}

void harness(void)
{
	trim();
	copy_string();
	digest_matches();
}
