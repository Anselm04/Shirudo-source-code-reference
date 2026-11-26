// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared compact duration formatter.
 */

#include <errno.h>
#include <stdio.h>

#include <shirudo/string.h>

#include "timefmt.h"

int format_duration(long seconds, char *buf, size_t cap)
{
	int n;

	if (seconds < 0)
		return strscpy(buf, "?", cap) < 0 ? -E2BIG : 0;
	if (seconds < 60)
		n = strsprintf(buf, cap, "%lds", seconds);
	else if (seconds < 3600)
		n = strsprintf(buf, cap, "%ldm", seconds / 60);
	else if (seconds < 86400)
		n = strsprintf(buf, cap, "%ldh", seconds / 3600);
	else
		n = strsprintf(buf, cap, "%ldd", seconds / 86400);
	return n < 0 ? -E2BIG : 0;
}

int iso8601(time_t t, char *out, size_t cap)
{
	struct tm tm;

	if (gmtime_r(&t, &tm) && strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm))
		return 0;
	if (cap)
		out[0] = '\0';
	return -EINVAL;
}
