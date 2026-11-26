/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a target's evidence says of its config history, key by key, for the
 * harnesses that prove util/config_attest.c on LEN events: json_parse()
 * hands it to a schema as util/json.h has it, whole or broken off at any
 * point, and SHA-256 gives any result.
 */

#ifndef SHIRUDO_PROOF_CONFIG_EVIDENCE_DOCUMENT_H
#define SHIRUDO_PROOF_CONFIG_EVIDENCE_DOCUMENT_H

#define HEX_TEXT	65

/* Not given, a key is absent or null. */
struct said_number {
	bool	given;
	__s64	value;
};

struct said_text {
	bool	given;
	char	text[HEX_TEXT];
};

struct said_event {
	struct said_number	sequence, kind;
	struct said_text	root_hash;
};

struct said_config {
	bool			config, events;
	struct said_number	schema, pcr, reset_count, restart_count;
	struct said_text	initial_pcr;
	struct said_event	event[LEN + 1];
};

static struct said_config said;
static bool breaks, broken, hash_failed;
static __u8 last_digest[32];

/* A static PCR the register leaves alone, or the config NvPCR's index. */
static bool config_register(__s64 pcr)
{
	return (pcr >= 0 && pcr <= 15 && pcr != CHAIN_PCR &&
		pcr != CHAIN_PHASE_PCR) || pcr == TPM_CONFIG_NVPCR_INDEX;
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	int ret;

	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	memcpy(last_digest, out, 32);
	if (ret)
		hash_failed = true;
	return ret;
}

/* Where breaks allows, the document is cut or malformed, with any error. */
static int breaks_here(void)
{
	int err;

	if (!breaks || !err)
		return 0;
	broken = true;
	return err;
}

static struct json_field *named(struct json_field *fields, size_t n,
				const char *key)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(fields[i].key, key))
			return &fields[i];
	return NULL;
}

/* A key the schema does not declare is parsed and discarded. */
static int give_number(struct json_field *field,
		       const struct said_number *number)
{
	if (!field || !number->given)
		return 0;
	if (field->type != JSON_T_INT)
		return -EINVAL;
	*(__s64 *)field->dst = number->value;
	field->seen = 1;
	return 0;
}

static int give_text(struct json_field *field, const struct said_text *text)
{
	char *dst;
	size_t i;

	if (!field || !text->given)
		return 0;
	if (field->type != JSON_T_STRING)
		return -EINVAL;
	dst = field->dst;
	for (i = 0; i < field->dst_cap; i++) {
		dst[i] = text->text[i];
		if (!text->text[i]) {
			field->seen = 1;
			return 0;
		}
	}
	return -ENOSPC;
}

static int give_event(struct json_field *fields, size_t n,
		      const struct said_event *event)
{
	size_t i;
	int ret;

	for (i = 0; i < n; i++)
		fields[i].seen = 0;
	ret = give_number(named(fields, n, "sequence"), &event->sequence);
	if (!ret)
		ret = give_number(named(fields, n, "kind"), &event->kind);
	if (!ret)
		ret = give_text(named(fields, n, "root_hash"),
				&event->root_hash);
	return ret;
}

/*
 * json_parse() as util/json.h has it: each declared key takes its value
 * once and is marked seen, null and an absent key leave it unseen, an array
 * hands each element over with the seen flags of its fields reset, and the
 * first error, the callback's included, ends the parse.
 */
int json_parse(const char *data, size_t len, struct json_field *fields,
	       size_t n_fields)
{
	struct json_field *config = named(fields, n_fields, "config");
	struct json_field *sub, *events;
	struct json_array *sink;
	size_t n_sub, i;
	int ret;

	__CPROVER_assert(config && config->type == JSON_T_OBJECT,
			 "a schema for the config object");
	sub = config->sub;
	n_sub = config->n_sub;
	events = named(sub, n_sub, "events");
	__CPROVER_assert(events && events->type == JSON_T_ARRAY,
			 "with an array of events");
	sink = events->dst;
	config->seen = 0;
	for (i = 0; i < n_sub; i++)
		sub[i].seen = 0;
	ret = breaks_here();
	if (ret || !said.config)
		return ret;
	ret = give_number(named(sub, n_sub, "schema"), &said.schema);
	if (!ret)
		ret = give_number(named(sub, n_sub, "pcr"), &said.pcr);
	if (!ret)
		ret = give_number(named(sub, n_sub, "reset_count"),
				  &said.reset_count);
	if (!ret)
		ret = give_number(named(sub, n_sub, "restart_count"),
				  &said.restart_count);
	if (!ret)
		ret = give_text(named(sub, n_sub, "initial_pcr"),
				&said.initial_pcr);
	if (ret)
		return ret;
	for (i = 0; said.events && i < LEN; i++) {
		ret = breaks_here();
		if (!ret)
			ret = give_event(events->sub, events->n_sub,
					 &said.event[i]);
		if (!ret)
			ret = sink->on_elem(sink->ctx);
		if (ret)
			return ret;
	}
	events->seen = said.events;
	ret = breaks_here();
	if (!ret)
		config->seen = 1;
	return ret;
}

static bool spells(const char *text, const __u8 *bytes)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (bytes[i] != hex_nibble(text[2 * i]) * 16 +
				hex_nibble(text[2 * i + 1]))
			return false;
	return true;
}

static bool blank(const struct config_evidence *view)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (view->initial_pcr[i] || view->value[i])
			return false;
	return !view->events && !view->n_events && !view->capacity &&
	       !view->reset_count && !view->restart_count && !view->pcr &&
	       !view->present;
}

#endif /* SHIRUDO_PROOF_CONFIG_EVIDENCE_DOCUMENT_H */
