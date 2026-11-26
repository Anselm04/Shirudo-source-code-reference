// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * config_evidence_emit() and config_evidence_parse() of
 * util/config_attest.c on every view of LEN events, the JSON writer
 * modelled as recording what is said under each key and json_parse() as
 * handing that to the schema: the parser returns exactly the views a
 * verifier can replay, with every field the writer was given.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/config_measure.c"
/* The C converts a __s64 and cuts a __u64 to bytes on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/chain.c"
#pragma CPROVER check pop
#include "../../../util/config_attest.c"
#include "config-evidence-document.h"

enum { OUTSIDE, IN_CONFIG, IN_EVENTS, IN_EVENT };

static int where;
static size_t n_said;

static struct said_number *number_at(const char *key)
{
	if (where == IN_CONFIG && !strcmp(key, "schema"))
		return &said.schema;
	if (where == IN_CONFIG && !strcmp(key, "pcr"))
		return &said.pcr;
	if (where == IN_CONFIG && !strcmp(key, "reset_count"))
		return &said.reset_count;
	if (where == IN_CONFIG && !strcmp(key, "restart_count"))
		return &said.restart_count;
	if (where == IN_EVENT && !strcmp(key, "sequence"))
		return &said.event[n_said].sequence;
	if (where == IN_EVENT && !strcmp(key, "kind"))
		return &said.event[n_said].kind;
	return NULL;
}

static struct said_text *text_at(const char *key)
{
	if (where == IN_CONFIG && !strcmp(key, "initial_pcr"))
		return &said.initial_pcr;
	if (where == IN_EVENT && !strcmp(key, "root_hash"))
		return &said.event[n_said].root_hash;
	return NULL;
}

/*
 * The writer of util/json.h for the calls this document takes: a member
 * goes under its key in the container open at the time, and any other call
 * fails the proof.
 */
void json_kv_int(struct json_emit *e, const char *key, __s64 val)
{
	struct said_number *number = number_at(key);

	__CPROVER_assert(number && !number->given,
			 "a number of the document, said once");
	number->given = true;
	number->value = val;
}

void json_kv_string(struct json_emit *e, const char *key, const char *val)
{
	struct said_text *text = text_at(key);
	size_t i;

	__CPROVER_assert(text && !text->given && strlen(val) < HEX_TEXT,
			 "a text of the document, said once");
	text->given = true;
	for (i = 0; i < HEX_TEXT; i++) {
		text->text[i] = val[i];
		if (!val[i])
			break;
	}
}

void json_obj_open_key(struct json_emit *e, const char *key)
{
	__CPROVER_assert(where == OUTSIDE && !said.config &&
			 !strcmp(key, "config"), "one config object");
	said.config = true;
	where = IN_CONFIG;
}

void json_arr_open(struct json_emit *e, const char *key)
{
	__CPROVER_assert(where == IN_CONFIG && !said.events &&
			 !strcmp(key, "events"), "one array of events in it");
	said.events = true;
	where = IN_EVENTS;
}

void json_obj_open(struct json_emit *e)
{
	__CPROVER_assert(where == IN_EVENTS && n_said < LEN,
			 "an event in the array");
	where = IN_EVENT;
}

void json_obj_close(struct json_emit *e)
{
	__CPROVER_assert(where == IN_EVENT || where == IN_CONFIG,
			 "closes the object it opened");
	if (where == IN_EVENT)
		n_said++;
	where = where == IN_EVENT ? IN_EVENTS : OUTSIDE;
}

void json_arr_close(struct json_emit *e)
{
	__CPROVER_assert(where == IN_EVENTS, "closes the array it opened");
	where = IN_CONFIG;
}

static bool same(const __u8 *a, const __u8 *b)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/* What replay() takes: a config register and one boot event, then updates. */
static bool replays(const struct config_evidence *view)
{
	const struct config_evidence_event *event = view->events;
	size_t i;

	if (!config_register(view->pcr) || !LEN)
		return false;
	for (i = 0; i < LEN; i++) {
		if (event[i].kind != (i ? CONFIG_EVENT_UPDATE :
					  CONFIG_EVENT_BOOT))
			return false;
		if (event[i].sequence < 1 || event[i].sequence > INT64_MAX)
			return false;
		if (i && event[i].sequence - event[i - 1].sequence != 1)
			return false;
	}
	return true;
}

static bool sequence_overflows(const struct config_evidence *view)
{
	size_t i;

	for (i = 0; i < LEN; i++)
		if (view->events[i].sequence > INT64_MAX)
			return true;
	return false;
}

static void check_read_back(const struct config_evidence *view,
			    const struct config_evidence *back)
{
	size_t i;

	__CPROVER_assert(back->present && back->pcr == view->pcr &&
			 back->reset_count == view->reset_count &&
			 back->restart_count == view->restart_count &&
			 same(back->initial_pcr, view->initial_pcr),
			 "the PCR, the TPM boot and the initial value");
	__CPROVER_assert(back->n_events == LEN, "every event");
	for (i = 0; i < LEN; i++)
		__CPROVER_assert(back->events[i].sequence ==
				 view->events[i].sequence &&
				 back->events[i].kind == view->events[i].kind &&
				 same(back->events[i].root_hash,
				      view->events[i].root_hash),
				 "each event, in its place");
}

void harness(void)
{
	struct config_evidence view, back;
	struct json_emit emit = {};
	char text[1];
	int err, ret;

	view.events = any_bytes(LEN * sizeof(*view.events));
	view.n_events = LEN;
	emit.err = err;
	ret = config_evidence_emit(&emit, &view);
	if (!view.present)
		__CPROVER_assert(!ret && !said.config,
				 "no history says nothing");
	else
		__CPROVER_assert(ret == (sequence_overflows(&view) ?
					 -EOVERFLOW : err),
				 "a sequence past a __s64 refused, the writer's error returned");
	if (ret)
		return;
	__CPROVER_assert(where == OUTSIDE &&
			 (!view.present || n_said == LEN),
			 "every event said and every container closed");

	ret = config_evidence_parse(text, sizeof(text), &back);
	if (!view.present) {
		__CPROVER_assert(!ret && blank(&back), "and reads back as none");
		return;
	}
	__CPROVER_assert(!ret == (replays(&view) && !hash_failed),
			 "reads back exactly what a verifier can replay");
	if (!ret)
		check_read_back(&view, &back);
	config_evidence_clear(&back);
}
