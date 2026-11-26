// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * elf_build_id_fd() on the binary a uprobe target names, which
 * the unsigned program metadata of a upatch chooses.
 */

#include "elf_target.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	__u8 build_id[UPATCH_BUILD_ID_MAX];
	char path[64];
	__u32 len;
	int fd;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	len = sizeof(build_id);
	elf_build_id_fd(fd, build_id, &len);
	close(fd);
	return 0;
}
