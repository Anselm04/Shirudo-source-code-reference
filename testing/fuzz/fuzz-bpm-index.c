// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_index_parse() on a repository index, and the order of the versions
 * it lists.
 */

#include <stdlib.h>

#include "bpm_oci.h"
#include "bpm_package.h"
#include "fuzz.h"

static int sign(int v)
{
	return (v > 0) - (v < 0);
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	static struct bpm_index_entry entries[BPM_MAX_ENTRIES];
	int n = 0;

	if (bpm_index_parse(data, size, entries, &n))
		return 0;
	/* install picks the newest version by this order: it must be one. */
	for (int i = 1; i < n; i++) {
		int ab = bpm_semver_compare(entries[i - 1].version,
					    entries[i].version);
		int ba = bpm_semver_compare(entries[i].version,
					    entries[i - 1].version);

		if (sign(ab) != -sign(ba))
			abort();
	}
	return 0;
}
