// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * push_index() of tools/shirudo-build/bpm-publish.c, which signs a
 * namespace's first repository index, against bpm_index_parse() of
 * util/bpm_package.c: the document it hands the signer the target reads
 * back as the one package, field by field. Registry and signer are stubs.
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
/* The registry calls push_index() makes are the stubs below. */
#include "bpm_oci.h"
#define bpm_oci_url		bpm_oci_url_unused
#define bpm_oci_get_memory	bpm_oci_get_memory_unused
#define bpm_oci_push_blob	bpm_oci_push_blob_unused
#define bpm_oci_put_manifest	bpm_oci_put_manifest_unused
#include "../../../util/bpm_oci.c"
#undef bpm_oci_url
#undef bpm_oci_get_memory
#undef bpm_oci_push_blob
#undef bpm_oci_put_manifest
#include "../../../util/bpm_package.c"
#include "../../../tools/shirudo-build/bpm-publish.c"

/* Room for the document of one short entry, of the 8 KiB asked for. */
#define DOC_MAX		512
/* The package pushed, and what push_index() did about it. */
static struct bpm_index_entry pushed;
static int allocations, documents, manifests;

/* The entries of the index, two of the 512 asked for. */
void *xcalloc(size_t nmemb, size_t size)
{
	static struct bpm_index_entry entries[2];

	__CPROVER_assert(nmemb == BPM_MAX_ENTRIES && size == sizeof(entries[0]),
			 "only the index's entries are allocated so");
	return entries;
}

/* In push_index()'s order: the document, its signature, the manifest. */
void *xmalloc(size_t size)
{
	static char document[DOC_MAX], signature[1], manifest[2 * DOC_MAX];

	switch (allocations++) {
	case 0:
		return document;
	case 1:
		return signature;
	default:
		return manifest;
	}
}

void xfree(void *p, size_t size)
{
}

void qsort(void *base, size_t nmemb, size_t size,
	   int (*compare)(const void *, const void *))
{
	__CPROVER_assert(nmemb == 1, "one entry, which needs no order");
}

int iso8601(time_t t, char *out, size_t cap)
{
	return strscpy(out, "2026-01-01T00:00:00Z", cap) < 0 ? -EINVAL : 0;
}

int bpm_oci_url(const struct bpm_oci_client *c, const char *repo,
		const char *kind, const char *ref, char *out, size_t sz)
{
	out[0] = '\0';
	return 0;
}

/* A namespace without an index, which --new-index starts. */
int bpm_oci_get_memory(struct bpm_oci_client *c, const char *url,
		       const char *accept, struct bpm_buffer *out)
{
	return -ENOENT;
}

int bpm_oci_push_blob(struct bpm_oci_client *c, const char *repository,
		      const void *body, size_t body_len, const char *media,
		      struct bpm_descriptor *out)
{
	bpm_copy_string(out->media, sizeof(out->media), media);
	bpm_copy_string(out->digest, sizeof(out->digest), "sha256:0");
	out->size = (__s64)body_len;
	return 0;
}

int bpm_oci_put_manifest(struct bpm_oci_client *c, const char *repository,
			 const char *reference, const __u8 *body,
			 size_t body_len, char *digest, size_t digest_sz)
{
	manifests++;
	return 0;
}

/* The signer, given the bytes the target will check and then read. */
int cms_sign(struct sign_io *io, const char *pkey_path, const char *cert_path)
{
	struct bpm_index_entry read[1];
	int n = 0, ret;

	documents++;
	ret = bpm_index_parse(io->insns, io->insns_sz, read, &n);
	__CPROVER_assert(!ret == (pushed.package_size > 0),
			 "an index the target reads, but for a package of no size");
	if (!ret)
		__CPROVER_assert(n == 1 && !strcmp(read[0].name, pushed.name) &&
				 !strcmp(read[0].version, pushed.version) &&
				 !strcmp(read[0].repository, pushed.repository) &&
				 !strcmp(read[0].manifest_digest,
					 pushed.manifest_digest) &&
				 !strcmp(read[0].package_digest,
					 pushed.package_digest) &&
				 !strcmp(read[0].signer, pushed.signer) &&
				 read[0].package_size == pushed.package_size,
				 "the one package, each field as it was pushed");
	io->signature_sz = sizeof(char);
	return 0;
}

void harness(void)
{
	static const __s64 sizes[] = { 1, INT64_MAX, 0, -1 };
	struct bpm_package_info info = {
		.name = "a", .version = "1.0.0", .signer = "5e",
	};
	struct bpm_descriptor layer = {
		.digest = "sha256:p", .size = sizes[LEN],
	};
	struct bpm_oci_client c;
	int ret;

	pushed = (struct bpm_index_entry){
		.name = "a", .version = "1.0.0", .repository = "ns/a",
		.manifest_digest = "sha256:m", .package_digest = "sha256:p",
		.signer = "5e", .package_size = sizes[LEN],
	};
	ret = push_index(&c, "ns/bpm-index", "ns/a", &info, "sha256:m", &layer,
			 "key", "cert", true);
	__CPROVER_assert(!ret && documents == 1 && manifests == 1,
			 "one document signed, one manifest put");
}
