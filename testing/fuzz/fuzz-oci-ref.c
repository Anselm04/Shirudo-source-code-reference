// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * An oci:// reference as an endpoint, a pull reference, a push repository
 * and a tree repository, and the registry URL built from what they accept.
 */

#include <stdlib.h>
#include <string.h>

#include "bpm_oci.h"
#include "fuzz.h"
#include "malloc.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/* Credentials from here, not from the auth file of whoever runs it. */
	setenv("BPM_OCI_USERNAME", "fuzz", 1);
	setenv("BPM_OCI_PASSWORD", "fuzz", 1);
	unsetenv("BPM_OCI_SCHEME");
	unsetenv("BPM_OCI_CA_FILE");
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME], url[PATH_MAX];
	struct bpm_oci_client c = {};
	char *ref;

	ref = xmalloc(size + 1);
	if (!ref)
		return 0;
	memcpy(ref, data, size);
	ref[size] = '\0';
	bpm_oci_parse_endpoint(ref, &c);
	if (!bpm_oci_parse_pull_ref(ref, &c, repository, sizeof(repository),
				    tag, sizeof(tag)))
		bpm_oci_url(&c, repository, "manifests", tag, url, sizeof(url));
	bpm_oci_parse_push_repo(ref, &c, repository, sizeof(repository));
	if (!bpm_oci_parse_tree_repo(ref, &c, repository, sizeof(repository)))
		bpm_oci_url(&c, repository, "blobs", ref, url, sizeof(url));
	xfree(ref, size + 1);
	return 0;
}
