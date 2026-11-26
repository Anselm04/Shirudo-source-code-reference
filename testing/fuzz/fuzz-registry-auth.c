// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The registry credentials in a container auth file, REGISTRY_AUTH_FILE:
 * a file that holds a NUL gives none, as the search for them would end
 * there.
 */

#include <stdlib.h>
#include <string.h>

#include "bpm_oci.h"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	unsetenv("BPM_OCI_USERNAME");
	unsetenv("BPM_OCI_SCHEME");
	unsetenv("BPM_OCI_CA_FILE");
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct bpm_oci_client c = {};
	char path[64];
	int fd, ret;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	setenv("REGISTRY_AUTH_FILE", path, 1);
	ret = bpm_oci_parse_endpoint("oci://registry.example:5000", &c);
	if (memchr(data, '\0', size) && (!ret || c.username[0]))
		abort();
	close(fd);
	return 0;
}
