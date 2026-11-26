// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The layer descriptors and index entries util/bpm_oci.c and
 * util/bpm_package.c take from a registry, into an empty table (LEN 0) or a
 * full one (LEN 1): one is kept exactly when whole and while room, a layer's
 * digest "sha256:" and 64 hex digits, and the next read into a cleared one.
 */

#include "proof.h"
#include "../../../util/bpm_package.c"
#include "../../../util/bpm_oci.c"
#include "../../../util/hex.c"

static bool hex_digit(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static bool sha256_digest(const char *d)
{
	size_t i;

	if (!str_has_prefix(d, "sha256:") || d[71])
		return false;
	for (i = 7; i < 71; i++)
		if (!hex_digit(d[i]))
			return false;
	return true;
}

static void terminate(char *s, size_t size)
{
	__CPROVER_assume(!s[size - 1]);
}

static void descriptor(void)
{
	struct bpm_descriptor items[1], was;
	struct desc_sink s;
	size_t i;
	int ret;

	s.items = items;
	s.max = 1;
	s.n = !!LEN;
	terminate(s.scratch.media, sizeof(s.scratch.media));
	terminate(s.scratch.digest, sizeof(s.scratch.digest));
	terminate(s.scratch.title, sizeof(s.scratch.title));
	was = s.scratch;
	ret = on_descriptor(&s);
	__CPROVER_assert(!ret == (!LEN && was.media[0] && was.size >= 0 &&
				  sha256_digest(was.digest)),
			 "a whole layer with a SHA-256 digest, while room");
	if (ret) {
		__CPROVER_assert(s.n == !!LEN, "a refused layer is not counted");
		return;
	}
	__CPROVER_assume(i < sizeof(was.digest));
	__CPROVER_assert(s.n == 1 && items[0].size == was.size &&
			 items[0].digest[i] == was.digest[i] &&
			 items[0].media[i] == was.media[i],
			 "the layer kept as read");
	__CPROVER_assert(!s.scratch.media[0] && !s.scratch.digest[0] &&
			 !s.scratch.title[0] && s.scratch.size == -1,
			 "the next layer read into a cleared one");
}

static void index_entry(void)
{
	struct bpm_index_entry *items, was;
	struct index_sink s;
	size_t i;
	int ret;

	items = any_bytes(sizeof(*items));
	s.items = items;
	s.n = LEN ? BPM_MAX_ENTRIES : 0;
	terminate(s.scratch.name, sizeof(s.scratch.name));
	terminate(s.scratch.version, sizeof(s.scratch.version));
	was = s.scratch;
	ret = on_index_entry(&s);
	__CPROVER_assert(!ret == (!LEN && bpm_name_ok(was.name) &&
				  bpm_version_ok(was.version) &&
				  was.repository[0] && was.manifest_digest[0] &&
				  was.package_digest[0] && was.package_size > 0),
			 "a whole entry with a valid name, while room");
	if (ret) {
		__CPROVER_assert(s.n == (LEN ? BPM_MAX_ENTRIES : 0),
				 "a refused entry is not counted");
		return;
	}
	__CPROVER_assume(i < sizeof(was.name));
	__CPROVER_assert(s.n == 1 && items[0].package_size == was.package_size &&
			 items[0].name[i] == was.name[i] &&
			 items[0].package_digest[i] == was.package_digest[i],
			 "the entry kept as read");
	__CPROVER_assert(!s.scratch.name[0] && !s.scratch.repository[0] &&
			 s.scratch.package_size == -1,
			 "the next entry read into a cleared one");
}

void harness(void)
{
	descriptor();
	index_entry();
}
