// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A kernel config, plain or gzip'd, as a upatch tree selector reads it,
 * and node.labels. A plain config that holds a NUL is refused: a line
 * read as a string would end there.
 */

#include "fuzz.h"
#include "bpm_tree_state.c"

static struct tree_selector sel;
static int slots[TREE_SELECTOR_HASH_SIZE];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static const char * const keys[] = {
		"CONFIG_BPF_LSM", "CONFIG_DEBUG_INFO_BTF", "CONFIG_LOCALVERSION",
		"CONFIG_LSM", "CONFIG_MODULES",
	};

	for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
		struct tree_selector_kv *kv;

		if (tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
					 TREE_MAX_KCONFIG, &kv) ||
		    strscpy(kv->key, keys[i], sizeof(kv->key)) < 0)
			abort();
	}
	selector_hash_build(&sel, slots);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	static char values[TREE_MAX_KCONFIG][TREE_STRING_MAX];
	static struct tree_kv labels[TREE_MAX_LABELS];
	bool found[TREE_MAX_KCONFIG] = {};
	char path[64];
	int fd, n;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	if (!read_selector_config_file(path, &sel, slots, values, found,
				       false) && memchr(data, '\0', size))
		abort();
	read_selector_config_file(path, &sel, slots, values, found, true);
	read_config_file(path, labels, &n, ARRAY_SIZE(labels));
	close(fd);
	return 0;
}
