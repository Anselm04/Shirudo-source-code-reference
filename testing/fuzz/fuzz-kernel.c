// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the kernel hands status: the ELF notes of /sys/kernel/notes.
 */
#include "fuzz.h"
#include "kernel_build_id.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char build_id[KERNEL_BUILD_ID_STRING_MAX];

	kernel_build_id_from_notes(data, size, build_id);
	return 0;
}
