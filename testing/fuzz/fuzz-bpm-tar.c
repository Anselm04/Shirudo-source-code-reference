// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_pkg_read_member_in() reading the Beefile out of a gzip'd package
 * archive.
 */

#include "bpm_package.h"
#include "fuzz.h"
#include "malloc.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char path[64], dir[256];
	size_t len = 0;
	__u8 *body;
	int fd;

	fd = fuzz_gzip_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	if (!bpm_pkg_read_member_in(path, "Beefile", NULL, dir, sizeof(dir),
				    &body, &len, 1 << 20))
		xfree(body, len + 1);
	close(fd);
	return 0;
}
