// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * config_evidence_parse() of util/config_attest.c on everything a target's
 * evidence can say of a config history of LEN events, key by key, whole or
 * broken off, json_parse() modelled by its contract: it takes exactly a
 * whole history in order, as said, and a refusal returns nothing and
 * leaves nothing allocated.
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

static bool hex_digits(const char *text, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (hex_nibble(text[i]) < 0)
			return false;
	return !text[n];
}

static bool count(const struct said_number *number)
{
	return number->given && number->value >= 0 &&
	       number->value <= UINT32_MAX;
}

/* Every key with a value of its kind, and an event or more. */
static bool whole(void)
{
	size_t i;

	if (!said.schema.given || said.schema.value != 1 ||
	    !said.pcr.given || !config_register(said.pcr.value) ||
	    !count(&said.reset_count) || !count(&said.restart_count) ||
	    !said.initial_pcr.given ||
	    !hex_digits(said.initial_pcr.text, 64) || !said.events || !LEN)
		return false;
	for (i = 0; i < LEN; i++) {
		const struct said_event *event = &said.event[i];

		if (!event->sequence.given || event->sequence.value < 1 ||
		    !event->kind.given ||
		    (event->kind.value != CONFIG_EVENT_BOOT &&
		     event->kind.value != CONFIG_EVENT_UPDATE) ||
		    !event->root_hash.given ||
		    !hex_digits(event->root_hash.text, 64))
			return false;
	}
	return true;
}

/* One boot event, then updates, each sequence number the one before plus 1. */
static bool in_order(void)
{
	size_t i;

	for (i = 0; i < LEN; i++) {
		if (said.event[i].kind.value != (i ? CONFIG_EVENT_UPDATE :
						     CONFIG_EVENT_BOOT))
			return false;
		if (i && said.event[i].sequence.value - 1 !=
			 said.event[i - 1].sequence.value)
			return false;
	}
	return true;
}

static void check_as_said(const struct config_evidence *view)
{
	size_t i;

	__CPROVER_assert(view->present &&
			 view->pcr == said.pcr.value &&
			 view->reset_count == said.reset_count.value &&
			 view->restart_count == said.restart_count.value &&
			 spells(said.initial_pcr.text, view->initial_pcr),
			 "the PCR, the TPM boot and the initial value said");
	__CPROVER_assert(view->n_events == LEN &&
			 view->n_events <= view->capacity,
			 "every event, inside its room");
	for (i = 0; i < LEN; i++)
		__CPROVER_assert(view->events[i].sequence ==
				 (__u64)said.event[i].sequence.value &&
				 (__s64)view->events[i].kind ==
				 said.event[i].kind.value &&
				 spells(said.event[i].root_hash.text,
					view->events[i].root_hash),
				 "each event as said, in the order said");
	for (i = 0; i < 32; i++)
		__CPROVER_assert(view->value[i] == last_digest[i],
				 "the value after the last event");
}

/*
 * A text ends within its 65 bytes: json_parse() refuses a longer one, which
 * a document broken off there covers.
 */
static void any_document(void)
{
	struct said_config any;
	size_t i;

	said = any;
	said.initial_pcr.text[HEX_TEXT - 1] = '\0';
	for (i = 0; i < LEN; i++)
		said.event[i].root_hash.text[HEX_TEXT - 1] = '\0';
	breaks = true;
}

void harness(void)
{
	struct config_evidence view;
	char text[1];
	int ret;

	any_document();
	ret = config_evidence_parse(text, sizeof(text), &view);
	if (ret || !said.config)
		__CPROVER_assert(blank(&view),
				 "a refusal and evidence without a history return nothing");
	else
		check_as_said(&view);
	if (!broken && !hash_failed) {
		__CPROVER_assert(!ret == (!said.config ||
					  (whole() && in_order())),
				 "takes exactly a whole history in order");
		__CPROVER_assert((ret == -EKEYREJECTED) ==
				 (said.config && whole() && !in_order()),
				 "and names one out of order as such");
	}
	config_evidence_clear(&view);
	__CPROVER_assert(blank(&view), "cleared, it holds nothing");
}
