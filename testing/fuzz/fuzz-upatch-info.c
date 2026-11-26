// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * upatch info on a .upatch, which it reads unverified, as text and as
 * JSON.
 */

#include "fuzz.h"

#include "../../builtin-upatch.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fuzz_output_capture();
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char path[64];
	int fd;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	fuzz_run(cmd_upatch_info, "info", path, NULL);
	fuzz_run(cmd_upatch_info, "info", path, "--json", NULL);
	close(fd);
	return 0;
}
