// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * on_event() and append_event() of util/config_attest.c, which take each
 * event of a target's evidence, on every event the JSON parser can hand
 * over and a history of LEN events: only a whole event with a positive
 * sequence, a known kind and a root of 64 hex digits joins it, never past
 * 4096 events, and a refusal leaves the history as it was.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/config_attest.c"

#define FIRST_ROOM	16
#define LIMIT_BYTES	(CONFIG_EVIDENCE_EVENTS_MAX * \
			 sizeof(struct config_evidence_event))

/*
 * The calloc() below util/malloc.c: room for more events than the limit
 * is never asked for, and is not given, as CBMC cannot carry such a block.
 */
void *calloc(size_t nmemb, size_t size)
{
	bool fails;

	__CPROVER_assert(nmemb == 1 && size <= LIMIT_BYTES,
			 "no room asked for past the limit");
	if (fails || nmemb != 1 || size > LIMIT_BYTES)
		return NULL;
	return __CPROVER_allocate(size, 1);
}

/* The room append_event() has made by the time it holds n events. */
static size_t room_for(size_t n)
{
	size_t room = n ? FIRST_ROOM : 0;

	while (room < n)
		room *= 2;
	return room;
}

static bool hex_digits(const char *text, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (hex_nibble(text[i]) < 0)
			return false;
	return !text[n];
}

static bool same_event(const struct config_evidence_event *a,
		       const struct config_evidence_event *b)
{
	size_t i;

	for (i = 0; i < sizeof(a->root_hash); i++)
		if (a->root_hash[i] != b->root_hash[i])
			return false;
	return a->sequence == b->sequence && a->kind == b->kind;
}

void harness(void)
{
	struct config_evidence_event *events = NULL, earlier = {};
	size_t room = room_for(LEN), at, i;
	struct config_evidence view = {};
	struct json_field fields[3];
	struct config_parser parser;
	bool whole, full;
	int ret;

	if (room)
		events = any_bytes(room * sizeof(*events));
	view.events = events;
	view.n_events = LEN;
	view.capacity = room;
	parser.view = &view;
	parser.event_fields = fields;
	parser.n_fields = ARRAY_SIZE(fields);
	/* json_parse() ends a string inside its dst_cap bytes. */
	parser.root_hash[sizeof(parser.root_hash) - 1] = '\0';
	/* CBMC cannot carry a read at any index of thousands of events. */
	if (at >= LEN || room > FIRST_ROOM)
		at = LEN ? LEN - 1 : 0;
	if (LEN)
		earlier = events[at];
	whole = fields[0].seen && fields[1].seen && fields[2].seen &&
		parser.sequence > 0 &&
		(parser.kind == CONFIG_EVENT_BOOT ||
		 parser.kind == CONFIG_EVENT_UPDATE) &&
		hex_digits(parser.root_hash, 64);
	full = !(LEN < CONFIG_EVIDENCE_EVENTS_MAX);

	ret = on_event(&parser);

	__CPROVER_assert(view.n_events <= view.capacity &&
			 view.capacity <= CONFIG_EVIDENCE_EVENTS_MAX,
			 "never past its room or the limit");
	__CPROVER_assert(!LEN || same_event(&view.events[at], &earlier),
			 "the events before it kept");
	if (ret) {
		__CPROVER_assert(ret == (!whole ? -EINVAL :
					 full ? -E2BIG : -ENOMEM),
				 "refuses a broken event, one past the limit or without memory");
		__CPROVER_assert(ret != -ENOMEM || LEN == room,
				 "memory asked only when the room is full");
		__CPROVER_assert(view.events == events &&
				 view.n_events == LEN && view.capacity == room,
				 "a refusal keeps the history as it was");
		return;
	}
	__CPROVER_assert(whole && !full, "a whole event, below the limit");
	__CPROVER_assert(view.n_events == LEN + 1 &&
			 view.events[LEN].sequence == (__u64)parser.sequence &&
			 (__s64)view.events[LEN].kind == parser.kind,
			 "joins with its sequence and kind");
	for (i = 0; i < sizeof(earlier.root_hash); i++)
		__CPROVER_assert(view.events[LEN].root_hash[i] ==
				 hex_nibble(parser.root_hash[2 * i]) * 16 +
				 hex_nibble(parser.root_hash[2 * i + 1]),
				 "and the root its digits spell");
}
