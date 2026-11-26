// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Human-readable formatters.
 */

#include <errno.h>
#include <stdio.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "format.h"

int human_size(__u64 bytes, char *out, size_t out_cap)
{
	double v = (double)bytes;
	const char *suf = "B";
	int n;

	if (bytes >= (1ULL << 30)) {
		v /= (double)(1ULL << 30);
		suf = "G";
	} else if (bytes >= (1ULL << 20)) {
		v /= (double)(1ULL << 20);
		suf = "M";
	} else if (bytes >= (1ULL << 10)) {
		v /= (double)(1ULL << 10);
		suf = "K";
	} else {
		return strsprintf(out, out_cap, "%llu%s", (__u64)bytes,
				  suf) < 0 ? -E2BIG : 0;
	}
	if (v >= 100.0)
		n = strsprintf(out, out_cap, "%.0f%s", v, suf);
	else if (v >= 10.0)
		n = strsprintf(out, out_cap, "%.1f%s", v, suf);
	else
		n = strsprintf(out, out_cap, "%.2f%s", v, suf);
	return n < 0 ? -E2BIG : 0;
}

void fputs_sanitized(const char *s, FILE *f)
{
	char shown[512];
	ssize_t n;

	n = strscpy(shown, s, sizeof(shown));
	if (n < 0)
		n = sizeof(shown) - 1;
	text_sanitize(shown, n, false);
	fputs(shown, f);
}
