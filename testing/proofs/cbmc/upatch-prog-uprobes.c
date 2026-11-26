// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata proof for a table of one program and a uprobe
 * target block, with the table's program count and the record's lengths
 * fixed: upatch-uprobe-targets proves parse_uprobe_targets() for every
 * block, and this one what prog_specs_parse() makes of each result.
 */

static void uprobe_record_lengths(void *metadata);
#define SHAPE_METADATA(metadata)	uprobe_record_lengths(metadata)

#include "upatch-prog-specs.c"

/*
 * A path and a build ID of one byte and one or two offsets, so that the
 * record ends 8 bytes before the table or at its end. With the lengths
 * alone fixed the proof takes 5.4 GB, and with neither it runs out of the
 * 6 GB CI gives it.
 */
static void uprobe_record_lengths(void *metadata)
{
	struct upatch_uprobe_target *record = (void *)((__u8 *)metadata +
		sizeof(struct upatch_prog_metadata) +
		NR_PROGS * sizeof(struct upatch_prog_entry) +
		sizeof(struct upatch_uprobe_targets));
	struct upatch_prog_metadata *md = metadata;
	bool two_offsets;

	md->nr_progs = cpu_to_le32(NR_PROGS);
	record->path_len = cpu_to_le32(1);
	record->build_id_len = cpu_to_le32(1);
	record->nr_offsets = cpu_to_le32(two_offsets ? 2 : 1);
}
