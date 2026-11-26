// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/string.h>

#include "kernel_release.h"

bool kernel_release_prefix_matches(const char *release,
				   const char *prefix)
{
	const char *rest;

	if (!release || !prefix)
		return false;
	if (!*prefix)
		return true;
	rest = str_after_prefix(release, prefix);
	return rest && (*rest == '\0' || *rest == '.' || *rest == '-');
}
