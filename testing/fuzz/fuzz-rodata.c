// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The .rodata view of a .upatch, as bpm info data reads it unverified.
 */

#include <fcntl.h>
#include <stdlib.h>

#include "fuzz.h"
#include "upatch.h"
#include "upatch_rodata.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

	if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0)
		abort();
	close(fd);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct rodata_range range;
	struct upatch u;
	__u32 offset;

	if (upatch_open_memory(data, size, &u))
		return 0;
	if (!upatch_rodata_data_offset(&u, &offset) &&
	    offset != u.hdr.rodata_data_off)
		abort();
	if (!upatch_rodata_symbol_range(&u, "fuzz_limits", &range) &&
	    (range.offset > u.hdr.data_len ||
	     range.size > u.hdr.data_len - range.offset))
		abort();
	if (!upatch_rodata_print(&u, "fuzz", false))
		fflush(stdout);
	if (!upatch_rodata_print(&u, "fuzz", true))
		fflush(stdout);
	upatch_close(&u);
	return 0;
}
