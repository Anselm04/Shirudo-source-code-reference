// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The decoders build_decoder_blob() of package.c writes for LEN decoders,
 * each of any manifest parse_decoder_manifest() takes from .rodata and a
 * short source: the section has the length the format gives,
 * parse_decoders() of util/upatch.c takes it, and upatch_decoder_view()
 * shows each manifest's values and names and each source.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <openssl/evp.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

#include "proof.h"

/*
 * CBMC's memcpy() makes all of a heap object symbolic when the length is,
 * and a loop makes an integer it fills so. A length the compiler knows
 * takes the first and any other the loop, which leaves the counts and
 * offsets the reader branches on the constants they are.
 */
static void *copy_bytes(void *dst, const void *src, size_t n, bool known)
{
	const __u8 *s = src;
	__u8 *d = dst;
	size_t i;

	if (known)
		return memcpy(dst, src, n);
	for (i = 0; i < n; i++)
		d[i] = s[i];
	return dst;
}

#define memcpy(dst, src, n) \
	copy_bytes(dst, src, n, __builtin_constant_p(n))

#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/upatch.c"
#include "../../../tools/shirudo-build/package.c"

#define NR_MAX		2
#define ENTRIES_END	(16 + 200 * LEN)

static const __u32 source_len[NR_MAX] = { 3, 1 };

static void short_name(char *name, char first, __u32 idx)
{
	name[0] = first;
	name[1] = (char)('0' + idx);
	name[2] = '\0';
}

/*
 * A manifest of any bytes, which for more than one decoder spells short
 * names, so that the lengths the writer copies are constants to CBMC.
 */
static const struct decoder_manifest *any_manifest(__u32 idx)
{
	struct decoder_manifest *m = any_bytes(sizeof(*m));

	if (LEN > 1) {
		short_name(m->upatch, 'u', idx);
		short_name(m->map, 'm', idx);
		short_name(m->source, 's', idx);
		short_name(m->entrypoint, 'e', idx);
	}
	return m;
}

/* The name the manifest's size bytes spell, padded with zeros. */
static bool same_name(const char *got, const char *manifest, size_t size)
{
	size_t n = strnlen(manifest, size), i;

	__CPROVER_assume(i < size);
	return got[i] == (i < n ? manifest[i] : '\0');
}

static void viewed(const struct upatch *u, __u32 idx,
		   const struct decoder_manifest *m, const char *source,
		   __u32 source_off)
{
	struct upatch_decoder_view d;
	__u32 i;

	__CPROVER_assert(!upatch_decoder_view(u, idx, &d), "viewed");
	__CPROVER_assert(d.language == get_le16(&m->language) &&
			 d.api_version == get_le16(&m->api_version) &&
			 d.input_format == get_le16(&m->input_format) &&
			 d.export_signal == get_le16(&m->export_signal),
			 "the language, API, input and signal of the manifest");
	__CPROVER_assert(same_name(d.upatch, m->upatch, sizeof(m->upatch)) &&
			 same_name(d.map, m->map, sizeof(m->map)) &&
			 same_name(d.source_name, m->source,
				   sizeof(m->source)) &&
			 same_name(d.entrypoint, m->entrypoint,
				   sizeof(m->entrypoint)),
			 "the names of the manifest");
	__CPROVER_assert((const __u8 *)d.source == u->map + source_off &&
			 d.source_len == source_len[idx],
			 "a source behind the entries and the sources before");
	for (i = 0; i < source_len[idx]; i++)
		__CPROVER_assert(u->map[source_off + i] == (__u8)source[i],
				 "the bytes of the source");
}

/* The shortest source with which a section passes what its length holds. */
static void refused(void)
{
	struct decoder_file big = { .source_len = UINT32_MAX - 215 };
	struct decoder_set set = { &big, 1 };
	__u32 len = 0xdeadbeef;
	void *out = (void *)1;

	__CPROVER_assert(build_decoder_blob(&set, &out, &len) == -EOVERFLOW &&
			 !out && !len,
			 "no section past what a length field holds");
}

void harness(void)
{
	const struct decoder_manifest *manifest[NR_MAX];
	__u32 len = 0xdeadbeef, off = ENTRIES_END, i;
	struct decoder_file items[NR_MAX];
	struct decoder_set set = { items, LEN };
	void *blob = (void *)1;
	struct upatch u = {};
	size_t n;

	for (i = 0; i < LEN; i++) {
		manifest[i] = any_manifest(i);
		/* collect_decoder_manifests() skips what this does not take. */
		__CPROVER_assume(parse_decoder_manifest((const void *)manifest[i],
							n, &items[i].manifest));
		/* decoder_set_add() refuses an empty source. */
		items[i].source = any_bytes(source_len[i]);
		items[i].source_len = source_len[i];
		off += source_len[i];
	}
	__CPROVER_assert(!build_decoder_blob(&set, &blob, &len), "built");
	if (!LEN) {
		__CPROVER_assert(!blob && !len, "no section without a decoder");
		refused();
		return;
	}
	__CPROVER_assert(blob && len == off,
			 "a section of the length the format gives");
	/* As just shown, so that CBMC takes both for the constants they are. */
	__CPROVER_assume(blob && len == off);
	u.map = blob;
	u.map_size = len;
	__CPROVER_assert(parse_decoders(&u, blob, len) &&
			 u.nr_decoders == LEN,
			 "the reader takes what the writer wrote");
	if (!u.decoder_blob)
		return;
	__CPROVER_assert(!get_le32(u.map + 12), "a zero reserved field");
	off = ENTRIES_END;
	for (i = 0; i < LEN; i++) {
		viewed(&u, i, manifest[i], items[i].source, off);
		off += source_len[i];
	}
	xfree(blob, len);
}
