// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The manifest of a tree publication, from bpm_tree_manifest() as bpm tree
 * append writes it to tree_manifest_canonical() as a node takes it, both
 * of util/bpm_package.c, for the payload and signature layers LEN picks:
 * bpm_oci_parse_manifest() reads back the two layers as written, and the
 * node takes those bytes as the canonical form; the layers swapped, or two
 * payloads in the publisher's own form, it refuses. The SHA-256 of the
 * empty config is a stub.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "../../../util/bpm_oci.c"
#include "../../../util/bpm_package.c"

/* Past the manifest, of the 8 KiB its callers ask for. */
#define DOC_MAX		768

#define DIGEST_A							\
	"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define DIGEST_B							\
	"sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	memset(out, 0x5a, 32);
	return 0;
}

/*
 * The allocator hands out objects of their sizes, so that the bytes
 * written are the bytes read back: the canonical form in DOC_MAX bytes of
 * the 8 KiB asked for, and two layers of the 512 the reader asks for.
 */
void *xmalloc(size_t size)
{
	static char want[DOC_MAX];

	__CPROVER_assert(size == BPM_TREE_MANIFEST_CAP,
			 "only the canonical form is allocated so");
	return want;
}

void *xcalloc(size_t nmemb, size_t size)
{
	static struct bpm_descriptor layers[2];

	__CPROVER_assert(nmemb == BPM_MAX_ENTRIES &&
			 size == sizeof(layers[0]), "only layers allocated so");
	return layers;
}

void xfree(void *p, size_t size)
{
}

static bool same(const struct bpm_descriptor *a,
		 const struct bpm_descriptor *b)
{
	return !strcmp(a->media, b->media) && !strcmp(a->digest, b->digest) &&
	       a->size == b->size;
}

void harness(void)
{
	static const __s64 sizes[][2] = {
		{ 0, 0 }, { 1, 4096 }, { INT64_MAX, 1 },
	};
	static char doc[DOC_MAX];
	struct bpm_descriptor payload = { .size = sizes[LEN][0] };
	struct bpm_descriptor sig = { .size = sizes[LEN][1] };
	struct bpm_descriptor layers[2], swapped[2];
	struct bpm_buffer manifest;
	size_t len;
	int n = 0;

	bpm_copy_string(payload.media, sizeof(payload.media), BPM_TREE_MEDIA);
	bpm_copy_string(payload.digest, sizeof(payload.digest), DIGEST_A);
	bpm_copy_string(sig.media, sizeof(sig.media), BPM_TREE_SIG_MEDIA);
	bpm_copy_string(sig.digest, sizeof(sig.digest), DIGEST_B);
	__CPROVER_assert(!bpm_tree_manifest(&payload, &sig, doc, sizeof(doc),
					    &len) && len < sizeof(doc),
			 "the manifest written");
	__CPROVER_assert(!bpm_oci_parse_manifest((const __u8 *)doc, len, layers,
						 2, &n, NULL, 0) &&
			 n == 2 && same(&layers[0], &payload) &&
			 same(&layers[1], &sig),
			 "which reads back as its two layers");
	manifest = (struct bpm_buffer){ (__u8 *)doc, len, sizeof(doc) };
	__CPROVER_assert(!tree_manifest_canonical(&manifest, layers, n),
			 "and is the canonical form of them");
	swapped[0] = layers[1];
	swapped[1] = layers[0];
	__CPROVER_assert(tree_manifest_canonical(&manifest, swapped, n) ==
			 -EBADMSG, "the layers swapped refused");
	/* Two payloads, written as the publisher would write them. */
	bpm_copy_string(sig.media, sizeof(sig.media), BPM_TREE_MEDIA);
	__CPROVER_assert(!bpm_tree_manifest(&payload, &sig, doc, sizeof(doc),
					    &len) &&
			 !bpm_oci_parse_manifest((const __u8 *)doc, len, layers,
						 2, &n, NULL, 0) && n == 2,
			 "a manifest of two payloads read");
	manifest = (struct bpm_buffer){ (__u8 *)doc, len, sizeof(doc) };
	__CPROVER_assert(tree_manifest_canonical(&manifest, layers, n) ==
			 -EBADMSG, "and refused, in its own form too");
}
