// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only `bpm tree show`: print a tree publication, or with --walk
 * every segment of it, verified as a node verifies it, with its document
 * bytes verbatim. The publisher fetches sealed segments through it too.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "bpm_oci.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "keys.h"
#include "help.h"
#include "log.h"
#include "options.h"
#include "malloc.h"

enum tree_show_opt {
	TREE_SHOW_CERT,
	TREE_SHOW_REFERENCE,
	TREE_SHOW_WALK,
};

static const struct opt_spec tree_show_opts[] = {
	[TREE_SHOW_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the certificate the tree is signed for" },
	[TREE_SHOW_REFERENCE] = { "--reference", 0, 0, "<ref>",
		"the tag of the publication (default stable)" },
	[TREE_SHOW_WALK] = { "--walk", 0, 0, NULL,
		"print every segment, oldest first, back from the one the "
		"reference names" },
};

static const struct help_section tree_show_sections[] = {
	HELP_OPTIONS("options:", tree_show_opts),
};

static const struct help tree_show_help = {
	.usage	    = "shirudo bpm tree show <repository> --cert <cert.der> "
		      "[--reference <ref>] [--walk]",
	.summary    = "Fetch the tree publication at <repository>:<ref>, verify "
		      "it against the\ncertificate as tree sync does, and print\n"
		      "{\"manifest_digest\":\"sha256:<hex>\",\"document\":"
		      "<document>} with the document's\nbytes verbatim, then a "
		      "newline.",
	.sections   = tree_show_sections,
	.n_sections = ARRAY_SIZE(tree_show_sections),
};

int build_tree_fetch_checked(struct bpm_oci_client *c, const char *repository,
			     const char *reference, const char *cert_path,
			     const struct trusted_set *trusted,
			     struct bpm_buffer *document,
			     struct tree_publication *pub,
			     char *manifest_digest, size_t digest_sz)
{
	struct bpm_buffer bytes = {};
	int ret;

	ret = bpm_tree_fetch_document(c, repository, reference, cert_path,
				      trusted, &bytes, manifest_digest,
				      digest_sz);
	if (!ret)
		ret = tree_parse((const char *)bytes.data, bytes.len, pub);
	if (!ret)
		ret = tree_publication_verify(pub, NULL);
	if (ret || !document)
		bpm_buffer_free(&bytes);
	else
		*document = bytes;
	return ret;
}

int build_tree_fetch_sealed(struct bpm_oci_client *c, const char *repository,
			    const char *cert_path,
			    const struct trusted_set *trusted,
			    const struct tree_publication *succ,
			    struct tree_publication *pred,
			    char *manifest_digest, size_t digest_sz)
{
	int ret;

	ret = build_tree_fetch_checked(c, repository,
				       succ->segment_manifest_digest,
				       cert_path, trusted, NULL, pred,
				       manifest_digest, digest_sz);
	if (ret)
		return ret;
	return tree_segment_precedes(pred, manifest_digest, succ);
}

static int tree_show_print(const char *manifest_digest,
			   const struct bpm_buffer *document)
{
	struct json_emit e = { .max = JSON_MAX_BYTES * 2 };
	int ret;

	json_obj_open(&e);
	json_kv_string(&e, "manifest_digest", manifest_digest);
	json_kv_raw(&e, "document", (const char *)document->data,
		    document->len);
	json_obj_close(&e);
	ret = e.err;
	if (!ret)
		ret = write_complete(STDOUT_FILENO, e.buf, e.len);
	if (!ret)
		ret = write_complete(STDOUT_FILENO, "\n", 1);
	xfree(e.buf, e.cap);
	return ret;
}

/*
 * The manifest digests of the sealed segments, newest first. Only these
 * are kept: the printing pass fetches each segment again by its digest,
 * which names the same bytes, so a long tree costs no more memory than
 * one document.
 */
struct tree_show_walk {
	__u8 (*digests)[32];
	size_t n, cap;
};

static void tree_show_walk_free(struct tree_show_walk *w)
{
	xfree(w->digests, w->cap * sizeof(*w->digests));
	*w = (struct tree_show_walk){};
}

static int tree_show_walk_add(struct tree_show_walk *w,
			      const char *manifest_digest)
{
	if (w->n == w->cap) {
		size_t cap = w->cap ? 2 * w->cap : 8;
		__u8 (*digests)[32];

		digests = xreallocarray(w->digests, w->cap, cap,
					sizeof(*digests));
		if (!digests)
			return -ENOMEM;
		w->digests = digests;
		w->cap = cap;
	}
	if (sha256_digest_decode(manifest_digest, w->digests[w->n]))
		return -EINVAL;
	w->n++;
	return 0;
}

/*
 * Back from tag to the segment at base.seq 0, each sealed segment
 * fetched by the digest its successor names and checked as the one it
 * names. A tree too long for a node to join is refused, as it is by
 * tree sync and bpm tree append.
 */
static int tree_show_walk_back(struct bpm_oci_client *c,
			       const char *repository,
			       const struct trusted_set *trusted,
			       const struct tree_publication *tag,
			       struct tree_show_walk *w)
{
	const struct tree_publication *succ = tag;
	struct tree_publication fetched[2] = {};
	char digest[BPM_MAX_DIGEST];
	int next = 0, ret;

	ret = tree_walk_within(tag->base_seq, 0);
	if (ret)
		pr_err("bpm tree show: the current segment starts after seq %lld, more than the %d operations a joining node walks",
		       (long long)tag->base_seq, TREE_MAX_JOIN_OPS);
	while (!ret && succ->base_seq > 0) {
		tree_publication_free(&fetched[next]);
		ret = build_tree_fetch_sealed(c, repository, NULL, trusted,
					      succ, &fetched[next], digest,
					      sizeof(digest));
		if (ret) {
			pr_err("bpm tree show: the sealed segment %s, which ends at seq %lld, cannot be fetched or does not verify",
			       succ->segment_manifest_digest,
			       (long long)succ->base_seq);
			break;
		}
		ret = tree_show_walk_add(w, digest);
		succ = &fetched[next];
		next ^= 1;
	}
	tree_publication_free(&fetched[0]);
	tree_publication_free(&fetched[1]);
	return ret;
}

/* A sealed segment the walk back checked, fetched and printed again. */
static int tree_show_sealed(struct bpm_oci_client *c, const char *repository,
			    const struct trusted_set *trusted,
			    const __u8 manifest_digest[32])
{
	char reference[BPM_MAX_DIGEST], digest[BPM_MAX_DIGEST];
	struct tree_publication pub = {};
	struct bpm_buffer document = {};
	int ret;

	sha256_digest_encode(manifest_digest, reference);
	ret = build_tree_fetch_checked(c, repository, reference, NULL, trusted,
				       &document, &pub, digest,
				       sizeof(digest));
	tree_publication_free(&pub);
	if (!ret && strcmp(digest, reference))
		ret = -EKEYREJECTED;
	if (ret)
		pr_err("bpm tree show: the sealed segment %s cannot be fetched again or changed",
		       reference);
	else
		ret = tree_show_print(digest, &document);
	bpm_buffer_free(&document);
	return ret;
}

static int tree_show_walk(struct bpm_oci_client *c, const char *repository,
			  const struct trusted_set *trusted,
			  const struct tree_publication *tag)
{
	struct tree_show_walk w = {};
	int ret;

	ret = tree_show_walk_back(c, repository, trusted, tag, &w);
	for (size_t i = w.n; !ret && i > 0; i--)
		ret = tree_show_sealed(c, repository, trusted,
				       w.digests[i - 1]);
	tree_show_walk_free(&w);
	return ret;
}

static int cmd_bpm_tree_show(int argc, const char **argv)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	const char *raw_repository = NULL, *cert = NULL;
	char repository[BPM_MAX_ENDPOINT], digest[BPM_MAX_DIGEST];
	const char *reference = "stable";
	struct trusted_set *trusted = NULL;
	struct tree_publication pub = {};
	struct bpm_buffer document = {};
	struct opt_parser p;
	bool walk = false;
	int ret, opt;

	OPT_INIT(&p, "bpm tree show", tree_show_opts, &tree_show_help, argc,
		 argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case TREE_SHOW_CERT:
			cert = p.value;
			break;
		case TREE_SHOW_REFERENCE:
			reference = p.value;
			break;
		case TREE_SHOW_WALK:
			walk = true;
			break;
		case OPT_ARG:
			if (raw_repository) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			raw_repository = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!raw_repository || !cert) {
		opt_usage(&p, "takes <repository> and --cert <cert.der>");
		return EXIT_USAGE;
	}
	ret = bpm_oci_parse_tree_repo(raw_repository, &c, repository,
				      sizeof(repository));
	if (ret) {
		pr_err("bpm tree show: the repository must be oci://registry/repository");
		return ret;
	}
	trusted = xcalloc(1, sizeof(*trusted));
	if (!trusted)
		return -ENOMEM;
	/*
	 * A node verifies against its config image's set; a set of this
	 * certificate alone takes the same path, so a refusal names the
	 * errno sync would.
	 */
	ret = keys_load_image_at(cert, -ENOENT, false, trusted);
	if (ret) {
		pr_err("bpm tree show: cannot read the certificate %s", cert);
		goto out;
	}
	ret = build_tree_fetch_checked(&c, repository, reference, NULL,
				       trusted, &document, &pub, digest,
				       sizeof(digest));
	if (!ret && walk)
		ret = tree_show_walk(&c, repository, trusted, &pub);
	if (!ret)
		ret = tree_show_print(digest, &document);
	tree_publication_free(&pub);
	bpm_buffer_free(&document);
out:
	xfree(trusted, sizeof(*trusted));
	return ret;
}

int build_bpm_tree_show(int argc, const char **argv)
{
	int ret;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		pr_err("bpm tree show: %s", strerror(EIO));
		return 1;
	}
	ret = cmd_bpm_tree_show(argc, argv);
	curl_global_cleanup();
	if (ret == EXIT_USAGE)
		return EXIT_USAGE;
	if (ret < 0)
		pr_err("bpm tree show: %s", strerror(-ret));
	return ret ? 1 : 0;
}
