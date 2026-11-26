// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "keepalive.h"

#define SCHEMA		"shirudo.keepalive/1"
#define HASH_HEX_LEN	(2 * CRYPTO_SHA256_LEN)

#define CODE_BITS	2
#define CODE_MAX	3
#define CODES_PER_BYTE	4

enum cond_code {
	COND_NOT_EVALUATED,
	COND_OK,
	COND_WARN,
	COND_ALERT,
};

/* The backend reads a pair by its place here: append, never reorder. */
static const char * const cond_order[] = {
	"LsmAttached",
	"KeyringSealed",
	"ChainIntact",
	"UpatchesMeasured",
	"TpmMeasured",
	"ConfigActive",
	"XdpCovered",
};

int keepalive_mask(const __u8 *codes, size_t n, char *b64, size_t cap)
{
	size_t len = DIV_ROUND_UP(n, CODES_PER_BYTE), i;
	__u8 raw[KEEPALIVE_MASK_BYTES] = {};

	if (n > KEEPALIVE_MASK_OPS)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		size_t slot = CODES_PER_BYTE - 1 - i % CODES_PER_BYTE;

		if (codes[i] > CODE_MAX)
			return -EINVAL;
		raw[i / CODES_PER_BYTE] |= codes[i] << (CODE_BITS * slot);
	}
	if (cap < BASE64_SIZE(len))
		return -E2BIG;
	return base64_encode(raw, len, b64, cap);
}

static enum cond_code cond_code_of(const char *status)
{
	if (!strcmp(status, "OK"))
		return COND_OK;
	if (!strcmp(status, "WARN"))
		return COND_WARN;
	if (!strcmp(status, "ALERT"))
		return COND_ALERT;
	return COND_NOT_EVALUATED;
}

static enum cond_code cond_code_named(const struct condition *conds, size_t n,
				      const char *type)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(conds[i].type, type))
			return cond_code_of(conds[i].status);
	return COND_NOT_EVALUATED;
}

__u16 keepalive_cond(const struct condition *conds, size_t n)
{
	__u16 cond = 0;
	size_t i;

	BUILD_BUG_ON(ARRAY_SIZE(cond_order) != CONDITIONS_MAX);
	BUILD_BUG_ON(CODE_BITS * ARRAY_SIZE(cond_order) > 8 * sizeof(cond));

	for (i = 0; i < ARRAY_SIZE(cond_order); i++)
		cond |= cond_code_named(conds, n, cond_order[i]) <<
			(CODE_BITS * i);
	return cond;
}

static bool is_hash(const char *s)
{
	return s && hex_is_lower(s, HASH_HEX_LEN) && !s[HASH_HEX_LEN];
}

static bool is_absent(const char *s)
{
	return !s || !s[0];
}

static bool is_hash_or_absent(const char *s)
{
	return is_absent(s) || is_hash(s);
}

static bool tree_is_valid(const struct keepalive_input *in)
{
	return !in->tree ||
	       (in->tree_id && is_hash_or_absent(in->base_root) &&
		is_hash(in->projection_root));
}

static bool input_is_valid(const struct keepalive_input *in)
{
	return in->boot_id && is_hash(in->version_id) &&
	       is_hash_or_absent(in->config_root) && in->kernel_release &&
	       is_hash_or_absent(in->image_root) && in->verdict &&
	       tree_is_valid(in) && is_hash(in->set_sha256);
}

static void kv_string_or_null(struct json_emit *e, const char *key,
			      const char *val)
{
	if (is_absent(val))
		json_kv_null(e, key);
	else
		json_kv_string(e, key, val);
}

static void kv_counters(struct json_emit *e, const char *key,
			const __u64 *count, size_t n)
{
	size_t i;

	if (!count) {
		json_kv_null(e, key);
		return;
	}
	json_arr_open(e, key);
	for (i = 0; i < n; i++)
		json_u64_value(e, count[i]);
	json_arr_close(e);
}

static void kv_no_tree(struct json_emit *e)
{
	static const char * const keys[] = {
		"tree_id", "generation", "base_seq", "last_seq", "base_root",
		"projection_root", "mask",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(keys); i++)
		json_kv_null(e, keys[i]);
}

static void kv_tree(struct json_emit *e, const struct keepalive_input *in)
{
	if (!in->tree) {
		kv_no_tree(e);
		return;
	}
	json_kv_string(e, "tree_id", in->tree_id);
	json_kv_u64(e, "generation", in->generation);
	json_kv_u64(e, "base_seq", in->base_seq);
	json_kv_u64(e, "last_seq", in->last_seq);
	kv_string_or_null(e, "base_root", in->base_root);
	json_kv_string(e, "projection_root", in->projection_root);
	if (in->mask)
		json_kv_string(e, "mask", in->mask);
	else
		json_kv_null(e, "mask");
}

static void body(struct json_emit *e, const struct keepalive_input *in)
{
	json_obj_open(e);
	json_kv_string(e, "schema", SCHEMA);
	json_kv_string(e, "boot_id", in->boot_id);
	json_kv_string(e, "version_id", in->version_id);
	kv_string_or_null(e, "config_root", in->config_root);
	json_kv_string(e, "kernel_release", in->kernel_release);
	kv_string_or_null(e, "image_id", in->image_id);
	kv_string_or_null(e, "image_version", in->image_version);
	kv_string_or_null(e, "image_root", in->image_root);
	json_kv_string(e, "verdict", in->verdict);
	json_kv_u64(e, "cond", in->cond);
	json_kv_u64(e, "flags", in->flags);
	kv_counters(e, "tamper", in->tamper, TAMPER_MAX);
	kv_counters(e, "integrity", in->integrity, INTEGRITY_MAX);
	kv_tree(e, in);
	json_kv_string(e, "set_sha256", in->set_sha256);
	json_kv_u64(e, "count", in->count);
	json_kv_u64(e, "not_ok", in->not_ok);
	json_obj_close(e);
}

static bool tree_state_same(const struct tree_state *a, int a_rc,
			    const struct tree_state *b, int b_rc)
{
	if (a_rc || b_rc)
		return a_rc == b_rc;
	return a->schema == b->schema && a->generation == b->generation &&
	       a->last_seq == b->last_seq && a->head_seq == b->head_seq &&
	       a->segment_base_seq == b->segment_base_seq &&
	       !strcmp(a->tree_id, b->tree_id) &&
	       !strcmp(a->projection_root, b->projection_root) &&
	       !strcmp(a->projection_root_tpm, b->projection_root_tpm) &&
	       !strcmp(a->manifest_digest, b->manifest_digest);
}

int keepalive_snapshot(const struct keepalive_snapshot_ops *ops, void *ctx,
		       struct tree_state *state, int *state_rc, __u32 *flags)
{
	bool pending = false, settled = false;
	struct tree_state again;
	int tries, again_rc, ret;

	for (tries = 0; tries < KEEPALIVE_SNAPSHOT_TRIES && !settled; tries++) {
		*state_rc = ops->read_state(ctx, state);
		pending = ops->pending(ctx);
		ret = ops->collect(ctx, state, *state_rc);
		if (ret)
			return ret;
		pending = ops->pending(ctx) || pending;
		again_rc = ops->read_state(ctx, &again);
		settled = tree_state_same(state, *state_rc, &again, again_rc);
	}
	if (pending)
		*flags |= KEEPALIVE_TREE_OP_PENDING;
	if (!settled)
		*flags |= KEEPALIVE_SNAPSHOT_UNSETTLED;
	return 0;
}

int keepalive_emit(const struct keepalive_input *in, char *buf, size_t cap,
		   size_t *len)
{
	struct json_emit e = { .buf = buf, .cap = cap };

	*len = 0;
	if (cap)
		buf[0] = '\0';
	if (!input_is_valid(in))
		return -EINVAL;
	body(&e, in);
	if (e.err) {
		if (cap)
			buf[0] = '\0';
		return e.err;
	}
	*len = e.len;
	return 0;
}
