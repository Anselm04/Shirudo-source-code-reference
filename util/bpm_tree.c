// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_oci.h"
#include "bpm_tree.h"
#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "malloc.h"
#include "upatch.h"

int tree_selector_kv_add(struct tree_selector_kv **kvs, int *n, int max,
			 struct tree_selector_kv **kv)
{
	struct tree_selector_kv *grown;

	if (*n >= max)
		return -E2BIG;
	grown = xreallocarray(*kvs, (size_t)*n, (size_t)*n + 1,
			      sizeof(**kvs));
	if (!grown)
		return -ENOMEM;
	*kvs = grown;
	*kv = &grown[(*n)++];
	return 0;
}

static int tree_kvs_copy(struct tree_selector_kv **dst,
			 const struct tree_selector_kv *src, int n)
{
	*dst = NULL;
	if (!n)
		return 0;
	*dst = xcalloc((size_t)n, sizeof(**dst));
	if (!*dst)
		return -ENOMEM;
	memcpy(*dst, src, (size_t)n * sizeof(**dst));
	return 0;
}

int tree_selector_copy(struct tree_selector *dst,
		       const struct tree_selector *src)
{
	*dst = *src;
	if (tree_kvs_copy(&dst->kconfig, src->kconfig, src->n_kconfig) ||
	    tree_kvs_copy(&dst->labels, src->labels, src->n_labels)) {
		tree_selector_free(dst);
		return -ENOMEM;
	}
	return 0;
}

void tree_selector_free(struct tree_selector *s)
{
	if (!s)
		return;
	xfree(s->kconfig, (size_t)s->n_kconfig * sizeof(*s->kconfig));
	xfree(s->labels, (size_t)s->n_labels * sizeof(*s->labels));
	s->kconfig = NULL;
	s->labels = NULL;
	s->n_kconfig = 0;
	s->n_labels = 0;
}

void tree_publication_free(struct tree_publication *pub)
{
	if (!pub)
		return;
	/* A slot past n_operations may hold an operation that failed to parse. */
	for (int i = 0; i < pub->operations_capacity; i++)
		tree_selector_free(&pub->operations[i].selector);
	xfree(pub->operations,
	      (size_t)pub->operations_capacity * sizeof(*pub->operations));
	*pub = (struct tree_publication){};
}

static int tree_operations_reserve(struct tree_publication *pub)
{
	struct tree_operation *operations;
	int old_capacity = pub->operations_capacity;
	int new_capacity = old_capacity ? old_capacity * 2 : 16;

	if (pub->n_operations >= TREE_MAX_OPS)
		return -E2BIG;
	if (pub->n_operations < old_capacity)
		return 0;
	if (new_capacity > TREE_MAX_OPS)
		new_capacity = TREE_MAX_OPS;
	operations = xreallocarray(pub->operations, (size_t)old_capacity,
				   (size_t)new_capacity, sizeof(*operations));
	if (!operations)
		return -ENOMEM;
	pub->operations = operations;
	pub->operations_capacity = new_capacity;
	return 0;
}

int tree_publication_append(struct tree_publication *pub,
			    const struct tree_operation *op)
{
	int ret;

	if (!pub || !op)
		return -EINVAL;
	ret = tree_operations_reserve(pub);
	if (ret)
		return ret;
	pub->operations[pub->n_operations] = *op;
	ret = tree_selector_copy(&pub->operations[pub->n_operations].selector,
				 &op->selector);
	if (ret) {
		memset(&pub->operations[pub->n_operations], 0,
		       sizeof(pub->operations[pub->n_operations]));
		return ret;
	}
	pub->n_operations++;
	return 0;
}

/* The operation the parse fills before tree_parse() keeps it. */
struct tree_reader {
	struct tree_publication	*pub;
	struct tree_operation	op;
	struct json_field	*lists;		/* the selector's three lists */
	char			value[TREE_STRING_MAX];
	char			pair[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int			n_pair;
};

struct tree_list {
	struct tree_reader	*r;
	char			(*values)[TREE_STRING_MAX];
	int			*n;
};

struct tree_map {
	struct tree_reader	*r;
	struct tree_selector_kv	**kvs;
	int			*n;
	int			max;
};

static int tree_list_value(void *ctx)
{
	struct tree_list *l = ctx;

	if (*l->n >= TREE_MAX_SELECTOR_VALUES ||
	    strscpy(l->values[*l->n], l->r->value, sizeof(l->values[0])) < 0)
		return -E2BIG;
	(*l->n)++;
	return 0;
}

/*
 * Each key of a kconfig or labels map once, with a list of one value or
 * more: a key twice would order the canonical form by however qsort()
 * places equal keys.
 */
static int tree_map_pair(void *ctx, const char *key)
{
	struct tree_map *m = ctx;
	struct tree_reader *r = m->r;
	struct tree_selector_kv *kv;
	int ret;

	if (!r->n_pair)
		return -EINVAL;
	for (int i = 0; i < *m->n; i++)
		if (!strcmp((*m->kvs)[i].key, key))
			return -EINVAL;
	ret = tree_selector_kv_add(m->kvs, m->n, m->max, &kv);
	if (ret)
		return ret;
	if (strscpy(kv->key, key, sizeof(kv->key)) < 0)
		return -E2BIG;
	memcpy(kv->values, r->pair, sizeof(kv->values));
	kv->n_values = r->n_pair;
	r->n_pair = 0;
	return 0;
}

static int tree_take_operation(void *ctx)
{
	struct tree_reader *r = ctx;
	struct tree_operation *o = &r->op;
	const struct tree_selector *s = &o->selector;
	const int counts[] = {
		s->n_kernel_release_prefix, s->n_kernel_build_id,
		s->n_architecture,
	};
	int ret;

	if (!o->id[0] || !o->op[0] || o->seq <= 0 ||
	    !o->operation_digest[0] || !o->artifact.repository[0] ||
	    !o->artifact.manifest_digest[0] ||
	    !o->artifact.layer_digest[0] ||
	    !o->artifact.payload_sha256[0])
		return -EINVAL;
	/* A selector list is one value or more, never []. */
	for (size_t i = 0; i < ARRAY_SIZE(counts); i++)
		if (r->lists[i].seen && !counts[i])
			return -EINVAL;
	ret = tree_operations_reserve(r->pub);
	if (ret)
		return ret;
	/* The publication takes over the operation's pairs. */
	r->pub->operations[r->pub->n_operations++] = *o;
	memzero_explicit(o, sizeof(*o));
	return 0;
}

int tree_parse(const char *body, size_t len,
	       struct tree_publication *out)
{
	struct tree_reader *r;
	struct tree_operation *o;
	__s64 schema = 0;
	int ret;

	if (!body || !out || len > JSON_MAX_BYTES)
		return -EINVAL;
	*out = (struct tree_publication){};
	r = xcalloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	r->pub = out;
	o = &r->op;
	{
		struct tree_list release = {
			r, o->selector.kernel_release_prefix,
			&o->selector.n_kernel_release_prefix,
		};
		struct tree_list build_id = {
			r, o->selector.kernel_build_id,
			&o->selector.n_kernel_build_id,
		};
		struct tree_list arch = {
			r, o->selector.architecture, &o->selector.n_architecture,
		};
		struct tree_list pair = { r, r->pair, &r->n_pair };
		struct tree_map kconfig = {
			r, &o->selector.kconfig, &o->selector.n_kconfig,
			TREE_MAX_KCONFIG,
		};
		struct tree_map labels = {
			r, &o->selector.labels, &o->selector.n_labels,
			TREE_MAX_LABELS,
		};
		struct json_array release_sink = { tree_list_value, &release };
		struct json_array build_id_sink = { tree_list_value, &build_id };
		struct json_array arch_sink = { tree_list_value, &arch };
		struct json_array pair_sink = { tree_list_value, &pair };
		struct json_map kconfig_map = { tree_map_pair, &kconfig };
		struct json_map labels_map = { tree_map_pair, &labels };
		struct json_array operations = { tree_take_operation, r };
		struct json_field value[] = {
			{ "", JSON_T_STRING, r->value, sizeof(r->value), 0, NULL,
			  0 },
		};
		struct json_field pair_value[] = {
			{ "", JSON_T_ARRAY, &pair_sink, 0, 0, value,
			  ARRAY_SIZE(value) },
		};
		struct json_field selector[] = {
			{ "kernel_release_prefix", JSON_T_ARRAY, &release_sink,
			  0, 0, value, ARRAY_SIZE(value) },
			{ "kernel_build_id", JSON_T_ARRAY, &build_id_sink, 0, 0,
			  value, ARRAY_SIZE(value) },
			{ "architecture", JSON_T_ARRAY, &arch_sink, 0, 0, value,
			  ARRAY_SIZE(value) },
			{ "kconfig", JSON_T_MAP, &kconfig_map, 0, 0, pair_value,
			  ARRAY_SIZE(pair_value) },
			{ "kernel_config", JSON_T_MAP, &kconfig_map, 0, 0,
			  pair_value, ARRAY_SIZE(pair_value) },
			{ "labels", JSON_T_MAP, &labels_map, 0, 0, pair_value,
			  ARRAY_SIZE(pair_value) },
		};
		struct json_field artifact[] = {
			{ "repository", JSON_T_STRING, o->artifact.repository,
			  sizeof(o->artifact.repository), 0, NULL, 0 },
			{ "manifest_digest", JSON_T_STRING,
			  o->artifact.manifest_digest,
			  sizeof(o->artifact.manifest_digest), 0, NULL, 0 },
			{ "layer_digest", JSON_T_STRING, o->artifact.layer_digest,
			  sizeof(o->artifact.layer_digest), 0, NULL, 0 },
			{ "payload_sha256", JSON_T_STRING,
			  o->artifact.payload_sha256,
			  sizeof(o->artifact.payload_sha256), 0, NULL, 0 },
		};
		struct json_field operation[] = {
			{ "seq", JSON_T_INT, &o->seq, 0, 0, NULL, 0 },
			{ "op", JSON_T_STRING, o->op, sizeof(o->op), 0, NULL, 0 },
			{ "id", JSON_T_STRING, o->id, sizeof(o->id), 0, NULL, 0 },
			{ "selector", JSON_T_OBJECT, NULL, 0, 0, selector,
			  ARRAY_SIZE(selector) },
			{ "artifact", JSON_T_OBJECT, NULL, 0, 0, artifact,
			  ARRAY_SIZE(artifact) },
			{ "operation_digest", JSON_T_STRING, o->operation_digest,
			  sizeof(o->operation_digest), 0, NULL, 0 },
		};
		struct json_field base[] = {
			{ "seq", JSON_T_INT, &out->base_seq, 0, 0, NULL, 0 },
			{ "segment_manifest_digest", JSON_T_STRING,
			  out->segment_manifest_digest,
			  sizeof(out->segment_manifest_digest), 0, NULL, 0 },
			{ "history_root", JSON_T_STRING, out->history_root,
			  sizeof(out->history_root), 0, NULL, 0 },
		};
		struct json_field head[] = {
			{ "seq", JSON_T_INT, &out->head_seq, 0, 0, NULL, 0 },
		};
		struct json_field root[] = {
			{ "schema", JSON_T_INT, &schema, 0, 0, NULL, 0 },
			{ "tree_id", JSON_T_STRING, out->tree_id,
			  sizeof(out->tree_id), 0, NULL, 0 },
			{ "generation", JSON_T_INT, &out->generation, 0, 0, NULL,
			  0 },
			{ "parent_manifest_digest", JSON_T_STRING,
			  out->parent_manifest_digest,
			  sizeof(out->parent_manifest_digest), 0, NULL, 0 },
			{ "base", JSON_T_OBJECT, NULL, 0, 0, base,
			  ARRAY_SIZE(base) },
			{ "operations", JSON_T_ARRAY, &operations, 0, 0,
			  operation, ARRAY_SIZE(operation) },
			{ "head", JSON_T_OBJECT, NULL, 0, 0, head,
			  ARRAY_SIZE(head) },
		};

		r->lists = selector;
		ret = json_parse(body, len, root, ARRAY_SIZE(root));
		if (!ret && (!root[0].seen || !root[2].seen || !root[4].seen ||
			     !base[0].seen || !root[5].seen || !root[6].seen ||
			     !head[0].seen))
			ret = -EINVAL;
	}
	if (ret && ret != -E2BIG && ret != -ENOMEM)
		ret = -EINVAL;
	if (!ret && (schema != 1 || !out->tree_id[0] ||
		     out->generation < 0 || out->generation == INT64_MAX ||
		     out->base_seq < 0 || out->head_seq < out->base_seq ||
		     out->head_seq == INT64_MAX))
		ret = -EINVAL;
	out->schema = (int)schema;
	/* Every operation's seq is positive, so seq - 1 cannot overflow. */
	for (int i = 0; !ret && i < out->n_operations; i++) {
		if (i && out->operations[i].seq - 1 != out->operations[i - 1].seq)
			ret = -EINVAL;
	}
	tree_selector_free(&r->op.selector);
	xfree(r, sizeof(*r));
	if (ret)
		tree_publication_free(out);
	return ret;
}

static int tree_selector_kv_compare(const void *left, const void *right)
{
	const struct tree_selector_kv *a =
		*(const struct tree_selector_kv * const *)left;
	const struct tree_selector_kv *b =
		*(const struct tree_selector_kv * const *)right;
	return strcmp(a->key, b->key);
}

/*
 * Canonical selector object: keys in lexicographic order, each list in
 * the publisher's order. Targets recompute operation digests from this
 * form, so publisher and consumer share one emitter.
 */
/*
 * A tree string holds no control character: the node cannot compute the
 * digest of an operation with one and refuses it, so a publication that
 * held one would go out signed and fail every later sync of the tree.
 */
static bool tree_text(const char *s)
{
	for (; *s; s++)
		if ((__u8)*s < 0x20)
			return false;
	return true;
}

static bool tree_texts(const char (*v)[TREE_STRING_MAX], int n)
{
	for (int i = 0; i < n; i++)
		if (!tree_text(v[i]))
			return false;
	return true;
}

static bool tree_kv_texts(const struct tree_selector_kv *kv, int n)
{
	for (int i = 0; i < n; i++)
		if (!tree_text(kv[i].key) ||
		    !tree_texts(kv[i].values, kv[i].n_values))
			return false;
	return true;
}

static bool tree_operation_text(const struct tree_operation *op)
{
	const struct tree_selector *s = &op->selector;
	const struct tree_artifact *a = &op->artifact;

	return tree_text(op->op) && tree_text(op->id) &&
	       tree_texts(s->kernel_release_prefix,
			  s->n_kernel_release_prefix) &&
	       tree_texts(s->kernel_build_id, s->n_kernel_build_id) &&
	       tree_texts(s->architecture, s->n_architecture) &&
	       tree_kv_texts(s->kconfig, s->n_kconfig) &&
	       tree_kv_texts(s->labels, s->n_labels) &&
	       tree_text(a->repository) && tree_text(a->manifest_digest) &&
	       tree_text(a->layer_digest) && tree_text(a->payload_sha256);
}

static int tree_emit_selector(struct json_emit *e,
			      const struct tree_selector *s)
{
	const struct tree_selector_kv *kconfig[TREE_MAX_KCONFIG];
	const struct tree_selector_kv *labels[TREE_MAX_LABELS];

	if (s->n_kconfig > (int)ARRAY_SIZE(kconfig) ||
	    s->n_labels > (int)ARRAY_SIZE(labels))
		return -E2BIG;
	for (int i = 0; i < s->n_kconfig; i++)
		kconfig[i] = &s->kconfig[i];
	for (int i = 0; i < s->n_labels; i++)
		labels[i] = &s->labels[i];
	qsort(kconfig, (size_t)s->n_kconfig, sizeof(kconfig[0]),
	      tree_selector_kv_compare);
	qsort(labels, (size_t)s->n_labels, sizeof(labels[0]),
	      tree_selector_kv_compare);

	json_obj_open_key(e, "selector");
	if (s->n_architecture) {
		json_arr_open(e, "architecture");
		for (int i = 0; i < s->n_architecture; i++)
			json_str(e, s->architecture[i]);
		json_arr_close(e);
	}
	if (s->n_kconfig) {
		json_obj_open_key(e, "kconfig");
		for (int i = 0; i < s->n_kconfig; i++) {
			json_arr_open(e, kconfig[i]->key);
			for (int j = 0; j < kconfig[i]->n_values; j++)
				json_str(e, kconfig[i]->values[j]);
			json_arr_close(e);
		}
		json_obj_close(e);
	}
	if (s->n_kernel_build_id) {
		json_arr_open(e, "kernel_build_id");
		for (int i = 0; i < s->n_kernel_build_id; i++)
			json_str(e, s->kernel_build_id[i]);
		json_arr_close(e);
	}
	if (s->n_kernel_release_prefix) {
		json_arr_open(e, "kernel_release_prefix");
		for (int i = 0; i < s->n_kernel_release_prefix; i++)
			json_str(e, s->kernel_release_prefix[i]);
		json_arr_close(e);
	}
	if (s->n_labels) {
		json_obj_open_key(e, "labels");
		for (int i = 0; i < s->n_labels; i++) {
			json_arr_open(e, labels[i]->key);
			for (int j = 0; j < labels[i]->n_values; j++)
				json_str(e, labels[i]->values[j]);
			json_arr_close(e);
		}
		json_obj_close(e);
	}
	json_obj_close(e);
	return 0;
}

static void tree_emit_artifact(struct json_emit *e,
			       const struct tree_artifact *a)
{
	json_obj_open_key(e, "artifact");
	json_kv_string(e, "repository", a->repository);
	json_kv_string(e, "manifest_digest", a->manifest_digest);
	json_kv_string(e, "layer_digest", a->layer_digest);
	json_kv_string(e, "payload_sha256", a->payload_sha256);
	json_obj_close(e);
}

/* The five keys the operation digest covers, into an open object. */
static int tree_emit_operation_keys(struct json_emit *e,
				    const struct tree_operation *op)
{
	int ret;

	if (!tree_operation_text(op))
		return -EINVAL;
	json_kv_int(e, "seq", op->seq);
	json_kv_string(e, "op", op->op);
	json_kv_string(e, "id", op->id);
	ret = tree_emit_selector(e, &op->selector);
	if (ret)
		return ret;
	tree_emit_artifact(e, &op->artifact);
	return 0;
}

static int tree_emit_operation(struct json_emit *e,
			       const struct tree_publication *pub, int index,
			       const struct tree_emit_extra *extra)
{
	const struct tree_operation *op = &pub->operations[index];
	int ret;

	json_obj_open(e);
	ret = tree_emit_operation_keys(e, op);
	if (!ret && extra)
		ret = extra->operation(e, index, extra->ctx);
	if (ret)
		return ret;
	json_kv_string(e, "operation_digest", op->operation_digest);
	json_obj_close(e);
	return e->err;
}

/*
 * The operation digest covers the canonical operation without the digest
 * field itself: seq, op, id, selector and artifact.
 */
int tree_operation_digest(const struct tree_operation *op,
			  char out[72])
{
	size_t body_cap = 1024u * 1024u;
	struct json_emit e;
	__u8 digest[32];
	char *body;
	int ret;

	body = xmalloc(body_cap);
	if (!body)
		return -ENOMEM;
	e = (struct json_emit){ .buf = body, .cap = body_cap };
	json_obj_open(&e);
	ret = tree_emit_operation_keys(&e, op);
	json_obj_close(&e);
	if (!ret)
		ret = e.err;
	if (!ret && sha256_buffer(body, e.len, digest))
		ret = -EIO;
	if (!ret)
		sha256_digest_encode(digest, out);
	xfree(body, body_cap);
	return ret;
}

static size_t tree_json_bound(const char *s)
{
	return 2 * strlen(s) + 4;
}

static size_t tree_selector_kv_bound(const struct tree_selector_kv *kv)
{
	size_t n = 8 + tree_json_bound(kv->key);

	for (int i = 0; i < kv->n_values; i++)
		n += tree_json_bound(kv->values[i]);
	return n;
}

static size_t tree_operation_bound(const struct tree_operation *op)
{
	const struct tree_selector *s = &op->selector;
	size_t n = 512;

	n += tree_json_bound(op->op) + tree_json_bound(op->id) +
	     tree_json_bound(op->operation_digest) +
	     tree_json_bound(op->artifact.repository) +
	     tree_json_bound(op->artifact.manifest_digest) +
	     tree_json_bound(op->artifact.layer_digest) +
	     tree_json_bound(op->artifact.payload_sha256);
	for (int i = 0; i < s->n_kernel_release_prefix; i++)
		n += tree_json_bound(s->kernel_release_prefix[i]);
	for (int i = 0; i < s->n_kernel_build_id; i++)
		n += tree_json_bound(s->kernel_build_id[i]);
	for (int i = 0; i < s->n_architecture; i++)
		n += tree_json_bound(s->architecture[i]);
	for (int i = 0; i < s->n_kconfig; i++)
		n += tree_selector_kv_bound(&s->kconfig[i]);
	for (int i = 0; i < s->n_labels; i++)
		n += tree_selector_kv_bound(&s->labels[i]);
	return n;
}

/*
 * Serialise a publication in the field order every publisher has used:
 * schema, tree_id, generation, parent_manifest_digest (when any), base
 * with its segment keys (when any), operations, head. The bound covers
 * the published form; the emitter grows past it only for keys extra adds.
 */
int tree_emit_publication(const struct tree_publication *pub,
			  const struct tree_emit_extra *extra,
			  char **out, size_t *out_len)
{
	struct json_emit e;
	size_t cap = 4096;
	char *body;
	int ret = 0;

	for (int i = 0; i < pub->n_operations; i++)
		cap += tree_operation_bound(&pub->operations[i]);
	body = xmalloc(cap);
	if (!body)
		return -ENOMEM;
	e = (struct json_emit){
		.buf = body, .cap = cap, .max = JSON_MAX_BYTES + 1,
	};
	json_obj_open(&e);
	json_kv_int(&e, "schema", pub->schema);
	json_kv_string(&e, "tree_id", pub->tree_id);
	json_kv_int(&e, "generation", pub->generation);
	if (pub->parent_manifest_digest[0])
		json_kv_string(&e, "parent_manifest_digest",
			       pub->parent_manifest_digest);
	json_obj_open_key(&e, "base");
	json_kv_int(&e, "seq", pub->base_seq);
	if (pub->segment_manifest_digest[0])
		json_kv_string(&e, "segment_manifest_digest",
			       pub->segment_manifest_digest);
	if (pub->history_root[0])
		json_kv_string(&e, "history_root", pub->history_root);
	json_obj_close(&e);
	json_arr_open(&e, "operations");
	for (int i = 0; !ret && i < pub->n_operations; i++)
		ret = tree_emit_operation(&e, pub, i, extra);
	json_arr_close(&e);
	json_obj_open_key(&e, "head");
	json_kv_int(&e, "seq", pub->head_seq);
	json_obj_close(&e);
	json_obj_close(&e);
	if (!ret)
		ret = e.err;
	/* tree_parse() takes JSON_MAX_BYTES at most. */
	if (!ret && e.len > JSON_MAX_BYTES)
		ret = -E2BIG;
	if (ret) {
		xfree(e.buf, e.cap);
		return ret;
	}
	*out = e.buf;
	*out_len = e.len;
	return 0;
}

int tree_operation_validate(const struct tree_operation *op)
{
	char expected[72];
	__u8 digest[32];

	if (op->seq <= 0 || !upatch_name_valid(op->id) ||
	    (strcmp(op->op, "add") && strcmp(op->op, "delete")))
		return -EINVAL;
	if (sha256_digest_decode(op->operation_digest, digest) ||
	    sha256_digest_decode(op->artifact.manifest_digest, digest) ||
	    sha256_digest_decode(op->artifact.layer_digest, digest) ||
	    sha256_digest_decode(op->artifact.payload_sha256, digest))
		return -EINVAL;
	if (tree_operation_digest(op, expected))
		return -EINVAL;
	return strcmp(op->operation_digest, expected) ? -EKEYREJECTED : 0;
}

static bool tree_base_valid(const struct tree_publication *pub)
{
	__u8 digest[32];

	if (pub->base_seq < 0)
		return false;
	if (!pub->base_seq)
		return !pub->segment_manifest_digest[0] &&
		       !pub->history_root[0];
	return pub->n_operations > 0 &&
	       !sha256_digest_decode(pub->segment_manifest_digest, digest) &&
	       !hex_decode(pub->history_root, digest, sizeof(digest));
}

int tree_publication_check(const struct tree_publication *pub)
{
	__u8 digest[32];
	int n = pub->n_operations;

	if (pub->parent_manifest_digest[0] &&
	    sha256_digest_decode(pub->parent_manifest_digest, digest))
		return -EINVAL;
	if (!tree_base_valid(pub))
		return -EINVAL;
	if (n && (pub->operations[0].seq != pub->base_seq + 1 ||
		  pub->head_seq != pub->operations[n - 1].seq))
		return -EINVAL;
	if (!n && pub->head_seq != pub->base_seq)
		return -EINVAL;
	return 0;
}

int tree_publication_verify(const struct tree_publication *pub, int *bad_op)
{
	int ret;

	if (bad_op)
		*bad_op = -1;
	/*
	 * The node records the tree ID in its state, which takes names
	 * alone: one that is not would be applied, measured and logged
	 * and then never recorded, failing every later sync.
	 */
	if (!bpm_package_name_ok(pub->tree_id))
		return -EINVAL;
	ret = tree_publication_check(pub);
	if (ret)
		return ret;
	for (int i = 0; i < pub->n_operations; i++) {
		ret = tree_operation_validate(&pub->operations[i]);
		if (ret) {
			if (bad_op)
				*bad_op = i;
			return ret;
		}
	}
	return 0;
}

int tree_publication_follows(const struct tree_publication *pub,
			     const struct tree_state *state,
			     const char *manifest_digest)
{
	bool same;

	if (!state)
		return pub->base_seq ? TREE_FOLLOWS_WALK : 0;
	if (strcmp(state->tree_id, pub->tree_id))
		return -EINVAL;
	same = !strcmp(state->manifest_digest, manifest_digest);
	if (!same && pub->generation <= state->generation)
		return -ERANGE;
	/*
	 * Only a direct successor names the manifest this node recorded
	 * as its parent; one that missed a generation never saw the parent.
	 */
	if (!same && pub->generation - 1 == state->generation &&
	    pub->parent_manifest_digest[0] &&
	    strcmp(pub->parent_manifest_digest, state->manifest_digest))
		return -ERANGE;
	if (pub->head_seq < state->last_seq)
		return -ERANGE;
	return pub->base_seq > state->last_seq ? TREE_FOLLOWS_WALK : 0;
}

int tree_segment_precedes(const struct tree_publication *pred,
			  const char *pred_manifest_digest,
			  const struct tree_publication *succ)
{
	if (succ->base_seq <= 0 ||
	    strcmp(succ->segment_manifest_digest, pred_manifest_digest) ||
	    strcmp(pred->tree_id, succ->tree_id) ||
	    pred->head_seq != succ->base_seq ||
	    pred->generation >= succ->generation)
		return -ERANGE;
	return 0;
}

int tree_walk_within(__s64 base_seq, __s64 last_seq)
{
	__s64 limit = last_seq ? TREE_MAX_WALK_OPS : TREE_MAX_JOIN_OPS;

	if (base_seq < 0 || last_seq < 0)
		return -EINVAL;
	return base_seq - last_seq > limit ? -E2BIG : 0;
}

int tree_history_at(const struct tree_publication *pub, __s64 seq,
		    __u8 out[32])
{
	__u8 digest[32];
	int ret;

	memset(out, 0, 32);
	if (seq < pub->base_seq || seq > pub->head_seq)
		return -EINVAL;
	if (pub->base_seq && hex_decode(pub->history_root, out, 32))
		return -EINVAL;
	for (int i = 0; i < pub->n_operations; i++) {
		if (pub->operations[i].seq > seq)
			break;
		if (sha256_digest_decode(pub->operations[i].operation_digest,
					 digest))
			return -EINVAL;
		ret = chain_history_step(out, digest, out);
		if (ret)
			return ret;
	}
	return 0;
}
