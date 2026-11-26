// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed sections compose_signed_data() of package.c lays behind
 * loader data of LEN bytes, for the name with an unload digest or with
 * attach metadata of 1 to ATTACH_MAX bytes: parse_signed_sections() of
 * util/upatch.c finds each where it was written, aligned, with its bytes
 * and length, the loader's data in front and zeros between.
 */

#define PROOF_MEMCHR_QUANTIFIED
/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <openssl/evp.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/upatch.c"
#include "../../../tools/shirudo-build/package.c"

#define ATTACH_MAX	8

static struct signed_section sections[UPATCH_SIGNED_SECTIONS_MAX];
static __u32 nr_sections;
static const char *name;

static void add_section(__u32 tag, const void *data, __u32 len)
{
	sections[nr_sections++] = (struct signed_section){ tag, data, len };
}

static __u32 offset(const struct upatch *u, const void *section)
{
	return (__u32)((const __u8 *)section - u->map);
}

/* Whether the reader kept the len bytes at p, aligned behind the data. */
static bool read_back(const struct upatch *u, const void *got, const void *p,
		      __u32 len)
{
	const __u8 *at = got, *bytes = p;
	__u32 i;

	if (!at || offset(u, at) & 7 || offset(u, at) < LEN)
		return false;
	__CPROVER_assume(i < len);
	return at[i] == bytes[i];
}

static bool inside(const struct upatch *u, const void *section, __u32 len,
		   __u32 at)
{
	return section && at >= offset(u, section) &&
	       at - offset(u, section) < len;
}

/* The name and one more section of len bytes, which the reader kept at got. */
static void composed(const __u8 *data, struct upatch *u, const void **got,
		     __u32 len)
{
	__u32 out_len = 0xdeadbeef, dir_off, i, j;
	void *out = (void *)1;

	__CPROVER_assert(!compose_signed_data(data, LEN, sections, nr_sections,
					      &out, &out_len), "composed");
	u->map = out;
	u->map_size = out_len;
	u->hdr.data_len = out_len;
	parse_signed_sections(u);
	__CPROVER_assert(read_back(u, u->signed_name, name, UPATCH_NAME_MAX),
			 "the name where the reader looks");
	if (LEN) {
		__CPROVER_assume(i < LEN);
		__CPROVER_assert(u->map[i] == data[i],
				 "the loader's data in front");
	}
	dir_off = get_le32(u->map + out_len - 8);
	__CPROVER_assert(!(dir_off & 7), "an aligned directory");
	__CPROVER_assume(j < dir_off);
	__CPROVER_assert(j < LEN || !u->map[j] ||
			 inside(u, u->signed_name, UPATCH_NAME_MAX, j) ||
			 inside(u, *got, len, j),
			 "zeros between the data and the sections");
	__CPROVER_assert(!u->decoder_blob && !u->signed_policy_labels,
			 "no section that was not written");
}

static void unload_directive(const __u8 *data)
{
	__u8 digest[UPATCH_PAYLOAD_HASH_LEN];
	struct upatch u = {};

	add_section(UPATCH_SECTION_UNLOAD, digest, sizeof(digest));
	composed(data, &u, (const void **)&u.signed_unload_payload,
		 sizeof(digest));
	__CPROVER_assert(read_back(&u, u.signed_unload_payload, digest,
				   sizeof(digest)),
			 "the digest where the reader looks");
	__CPROVER_assert(!u.signed_attach, "no attach metadata");
	xfree((void *)u.map, u.map_size);
}

static void load(const __u8 *data, __u32 attach_len)
{
	const __u8 *attach = any_bytes(attach_len);
	struct upatch u = {};

	add_section(UPATCH_SECTION_ATTACH, attach, attach_len);
	composed(data, &u, (const void **)&u.signed_attach, attach_len);
	__CPROVER_assert(u.signed_attach_len == attach_len &&
			 read_back(&u, u.signed_attach, attach, attach_len),
			 "the attach metadata where the reader looks");
	__CPROVER_assert(!u.signed_unload_payload, "no unload digest");
	xfree((void *)u.map, u.map_size);
}

/* A count the reader refuses, and a length that passes what a field holds. */
static void refused(const __u8 *data)
{
	struct signed_section big[2] = { { .len = UINT32_MAX } };
	__u32 nr, len = 0xdeadbeef;
	void *out = (void *)1;

	__CPROVER_assume(!nr || nr > UPATCH_SIGNED_SECTIONS_MAX);
	__CPROVER_assert(compose_signed_data(data, LEN, sections, nr, &out,
					     &len) == -EINVAL && !out && !len,
			 "no directory of a size the reader refuses");
	out = (void *)1;
	len = 0xdeadbeef;
	__CPROVER_assert(compose_signed_data(data, LEN, big, 2, &out,
					     &len) == -EOVERFLOW && !out && !len,
			 "no data past what a length field holds");
}

#ifndef LOAD_SECTIONS
void harness(void)
{
	const __u8 *data = any_bytes(LEN);
	__u32 attach_len, k;

	/* finalize_object() signs a name its strscpy() fit into 256 bytes. */
	name = any_bytes(UPATCH_NAME_MAX);
	__CPROVER_assume(k < UPATCH_NAME_MAX && !name[k]);
	add_section(UPATCH_SECTION_NAME, name, UPATCH_NAME_MAX);
	unload_directive(data);
	for (attach_len = 1; attach_len <= ATTACH_MAX; attach_len++) {
		nr_sections = 1;
		load(data, attach_len);
	}
	refused(data);
}
#endif
