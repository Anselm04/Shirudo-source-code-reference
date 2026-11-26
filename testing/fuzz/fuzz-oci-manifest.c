// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_oci_parse_manifest() on what a registry returns, before anything
 * about it is verified.
 */

#include "bpm_oci.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	static struct bpm_descriptor layers[16];
	char name[BPM_MAX_NAME];
	int n = 0;

	bpm_oci_parse_manifest(data, size, layers, ARRAY_SIZE(layers), &n,
			       name, sizeof(name));
	return 0;
}
