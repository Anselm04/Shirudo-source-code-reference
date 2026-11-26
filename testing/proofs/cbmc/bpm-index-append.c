// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * push_index() of tools/shirudo-build/bpm-publish.c on a namespace whose
 * index lists one package, which bpm_index_parse() of util/bpm_package.c
 * reads: the target reads the index signed next with the package kept and
 * the pushed one in order, a version pushed again once, and a version
 * with other content is refused unsigned. LEN picks the case.
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
/* The registry and the signature check are the stubs below. */
#include "bpm_oci.h"
#include "bpm_package.h"
#define bpm_oci_url		bpm_oci_url_unused
#define bpm_oci_get_memory	bpm_oci_get_memory_unused
#define bpm_oci_get_blob	bpm_oci_get_blob_unused
#define bpm_oci_parse_manifest	bpm_oci_parse_manifest_unused
#define bpm_oci_push_blob	bpm_oci_push_blob_unused
#define bpm_oci_put_manifest	bpm_oci_put_manifest_unused
#define bpm_sha256_hex		bpm_sha256_hex_unused
#define bpm_digest_matches	bpm_digest_matches_unused
#define bpm_buffer_free		bpm_buffer_free_unused
#define bpm_verify_cms		bpm_verify_cms_unused
#include "../../../util/bpm_oci.c"
#include "../../../util/bpm_package.c"
#undef bpm_oci_url
#undef bpm_oci_get_memory
#undef bpm_oci_get_blob
#undef bpm_oci_parse_manifest
#undef bpm_oci_push_blob
#undef bpm_oci_put_manifest
#undef bpm_sha256_hex
#undef bpm_digest_matches
#undef bpm_buffer_free
#undef bpm_verify_cms
#include "../../../tools/shirudo-build/bpm-publish.c"

enum { APPENDED, AGAIN, CHANGED };

/* Room for the document of two short entries, of the 12 KiB asked for. */
#define DOC_MAX		512

#define ENTRY(name, repository, digest)					\
	"{\"schema\":1,\"generated_at\":\"2026-01-01T00:00:00Z\","	\
	"\"packages\":[{\"name\":\"" name "\",\"version\":\"1.0.0\","	\
	"\"repository\":\"" repository "\","				\
	"\"manifest_digest\":\"sha256:m\","				\
	"\"package_digest\":\"sha256:" digest "\",\"package_size\":5,"	\
	"\"signer_fingerprint\":\"5e\"}]}"

/* The index the registry serves, as an earlier push signed it. */
static const char *const listed[] = {
	[APPENDED] = ENTRY("b", "ns/b", "p"),
	[AGAIN] = ENTRY("a", "ns/a", "p"),
	[CHANGED] = ENTRY("a", "ns/a", "q"),
};

/* Which of the cases this run is. */
static const int pushed = LEN;

static int allocations, documents, manifests;

/* First the index's entries, two of 512, then the manifest's layers. */
void *xcalloc(size_t nmemb, size_t size)
{
	static struct bpm_index_entry entries[2];
	static struct bpm_descriptor layers[2];

	if (size == sizeof(entries[0]))
		return entries;
	__CPROVER_assert(size == sizeof(layers[0]), "entries or layers");
	return layers;
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

void pr_err(const char *fmt, ...)
{
}

/* Two entries at most, in the order the index keeps. */
void qsort(void *base, size_t nmemb, size_t size,
	   int (*compare)(const void *, const void *))
{
	struct bpm_index_entry *entry = base, first;

	__CPROVER_assert(nmemb <= 2 && size == sizeof(*entry),
			 "two entries at most");
	if (nmemb < 2 || compare(&entry[0], &entry[1]) <= 0)
		return;
	first = entry[0];
	entry[0] = entry[1];
	entry[1] = first;
}

int iso8601(time_t t, char *out, size_t cap)
{
	return strscpy(out, "2026-01-02T00:00:00Z", cap) < 0 ? -EINVAL : 0;
}

int bpm_oci_url(const struct bpm_oci_client *c, const char *repo,
		const char *kind, const char *ref, char *out, size_t sz)
{
	out[0] = '\0';
	return 0;
}

int bpm_oci_get_memory(struct bpm_oci_client *c, const char *url,
		       const char *accept, struct bpm_buffer *out)
{
	return 0;
}

/* The index's manifest: its document and its signature, sizes unsaid. */
int bpm_oci_parse_manifest(const __u8 *body, size_t len,
			   struct bpm_descriptor *layers, int max_layers,
			   int *n_layers, char *package_name,
			   size_t package_name_sz)
{
	bpm_copy_string(layers[0].media, sizeof(layers[0].media),
			BPM_INDEX_MEDIA);
	bpm_copy_string(layers[1].media, sizeof(layers[1].media),
			BPM_INDEX_SIG_MEDIA);
	layers[0].size = -1;
	layers[1].size = -1;
	*n_layers = 2;
	return 0;
}

int bpm_oci_get_blob(struct bpm_oci_client *c, const char *url,
		     const char *accept, struct bpm_buffer *out)
{
	static __u8 signature[1];

	if (strcmp(accept, BPM_INDEX_MEDIA)) {
		out->data = signature;
		out->len = sizeof(signature);
		return 0;
	}
	out->data = (__u8 *)listed[pushed];
	out->len = strlen(listed[pushed]);
	return 0;
}

int bpm_sha256_hex(const void *data, size_t len, char *hex, size_t hex_sz)
{
	hex[0] = '\0';
	return 0;
}

bool bpm_digest_matches(const char *want, const char *hex)
{
	return true;
}

int bpm_verify_cms(const __u8 *payload, size_t payload_len,
		   const __u8 *sig, size_t sig_len, const char *cert_path)
{
	return 0;
}

void bpm_buffer_free(struct bpm_buffer *b)
{
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

static bool is_package(const struct bpm_index_entry *e, const char *name,
		       const char *repository, __s64 size)
{
	return !strcmp(e->name, name) && !strcmp(e->version, "1.0.0") &&
	       !strcmp(e->repository, repository) &&
	       !strcmp(e->manifest_digest, "sha256:m") &&
	       !strcmp(e->package_digest, "sha256:p") &&
	       !strcmp(e->signer, "5e") && e->package_size == size;
}

/* The signer, given the bytes the target will check and then read. */
int cms_sign(struct sign_io *io, const char *pkey_path, const char *cert_path)
{
	struct bpm_index_entry read[2];
	int n = 0;

	documents++;
	__CPROVER_assert(!bpm_index_parse(io->insns, io->insns_sz, read, &n),
			 "an index the target reads");
	__CPROVER_assert(n == (pushed == APPENDED ? 2 : 1) &&
			 is_package(&read[0], "a", "ns/a", 7),
			 "the package pushed, once, before those behind it");
	__CPROVER_assert(pushed != APPENDED ||
			 is_package(&read[1], "b", "ns/b", 5),
			 "the package listed before kept as it was");
	io->signature_sz = sizeof(char);
	return 0;
}

void harness(void)
{
	struct bpm_package_info info = {
		.name = "a", .version = "1.0.0", .signer = "5e",
	};
	struct bpm_descriptor layer = { .digest = "sha256:p", .size = 7 };
	struct bpm_oci_client c;
	int ret;

	ret = push_index(&c, "ns/bpm-index", "ns/a", &info, "sha256:m", &layer,
			 "key", "cert", false);
	if (pushed == CHANGED) {
		__CPROVER_assert(ret == -EEXIST && !documents && !manifests,
				 "a version with other content refused unsigned");
		return;
	}
	__CPROVER_assert(!ret && documents == 1 && manifests == 1,
			 "one document signed, one manifest put");
}
