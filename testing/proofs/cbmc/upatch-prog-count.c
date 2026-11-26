// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * prog_specs_parse() of util/upatch.c with the program count of a header
 * no signature covers, any count larger than the LEN bytes of metadata
 * hold: it refuses before it allocates the table or reads an entry.
 */

#include "proof.h"
#include "../../../util/malloc.c"

/* upatch-prog-specs proves the table that fits; this one never gets one. */
#define xcalloc table_for_a_count_that_does_not_fit
static void *table_for_a_count_that_does_not_fit(size_t n, size_t size)
{
	__CPROVER_assert(false, "no table for a count the metadata cannot hold");
	return NULL;
}

#include "../../../util/upatch.c"
#undef xcalloc

#define ENTRIES_LEN	(LEN - (__s64)sizeof(struct upatch_prog_metadata))
#define NR_FIT		(ENTRIES_LEN < 0 ? 0 : \
			 ENTRIES_LEN / sizeof(struct upatch_prog_entry))

void harness(void)
{
	struct prog_spec *specs = (void *)1;
	__u32 nr_progs, nr_maps;
	__u8 *metadata;
	int ret;

	__CPROVER_assume(nr_progs > NR_FIT);
	metadata = any_bytes(LEN);
	ret = prog_specs_parse(metadata, LEN, nr_maps, nr_progs, &specs);
	__CPROVER_assert(ret < 0 && !specs, "refused, with no specs");
}
