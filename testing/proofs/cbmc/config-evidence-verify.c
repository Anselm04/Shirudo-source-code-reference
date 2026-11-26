// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * replay() and config_evidence_verify() of util/config_attest.c on every
 * history of LEN events: a history passes only as one boot event and then
 * updates in sequence, and only when the quoted PCR, or the certified
 * config NvPCR from the value systemd initializes it to, holds the initial
 * value extended by each event's digest in order. SHA-256 gives any digest
 * or fails: nothing is assumed of it, collision resistance least of all.
 */

#include "proof.h"
#include "../../../util/config_measure.c"
/* The C converts a __s64 and cuts a __u64 to bytes on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/chain.c"
#pragma CPROVER check pop
#include "../../../util/config_attest.c"

static const char event_tag[] = "shirudo-config-root-v1";

#define EVENT_BYTES	(sizeof(event_tag) + 4 + 32)
#define EXTEND_BYTES	64

/* A PCR that the history's events extend, as far as they were hashed. */
static const struct config_evidence *history;
static __u8 pcr_now[32], event_digest[32];
static size_t n_extended;
static bool digest_ready, initial_asked, hash_failed;

/* SHA-256 of 64 zero bytes, one value however often asked. */
static __u8 nvpcr_initial[32];

static bool same(const __u8 *a, const __u8 *b)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/*
 * The event digest of the next event: the tag and its NUL, the kind as 32
 * bits most significant byte first, 1 for the boot event and 2 for an
 * update, and the root.
 */
static void check_event(const __u8 *in)
{
	size_t k;

	__CPROVER_assert(!digest_ready && n_extended < LEN,
			 "one digest for each event in turn");
	for (k = 0; k < sizeof(event_tag); k++)
		__CPROVER_assert(in[k] == (__u8)event_tag[k],
				 "the tag and its NUL");
	__CPROVER_assert(!in[k] && !in[k + 1] && !in[k + 2] &&
			 in[k + 3] == (n_extended ? 2 : 1),
			 "boot as 1 and update as 2");
	__CPROVER_assert(same(in + k + 4,
			      history->events[n_extended].root_hash),
			 "the event's root");
}

/*
 * The config NvPCR's value once systemd's unlogged initializing write
 * extended 64 zero bytes, asked of an NvPCR history before its first
 * event. A first extend without its event's digest comes here as well
 * and fails on its bytes.
 */
static void check_initial(const __u8 *in)
{
	size_t k;

	__CPROVER_assert(history->pcr == TPM_CONFIG_NVPCR_INDEX && !n_extended,
			 "the NvPCR's start, before any event");
	for (k = 0; k < EXTEND_BYTES; k++)
		__CPROVER_assert(!in[k], "64 zero bytes");
}

/* A TPM's extend: the PCR's value, then the event's digest. */
static void check_extend(const __u8 *in)
{
	__CPROVER_assert(digest_ready, "an extend after its event's digest");
	__CPROVER_assert(same(in, pcr_now) && same(in + 32, event_digest),
			 "the PCR extended by the event's digest");
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	int ret;

	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_assert(len == EVENT_BYTES || len == EXTEND_BYTES,
			 "an event or an extend");
	if (len == EXTEND_BYTES && !digest_ready && !initial_asked) {
		check_initial(data);
		initial_asked = true;
		memcpy(out, nvpcr_initial, 32);
		if (ret)
			hash_failed = true;
		return ret;
	}
	if (len == EVENT_BYTES)
		check_event(data);
	else
		check_extend(data);
	__CPROVER_havoc_slice(out, 32);
	if (len == EVENT_BYTES) {
		memcpy(event_digest, out, 32);
		digest_ready = true;
	} else {
		memcpy(pcr_now, out, 32);
		digest_ready = false;
		n_extended++;
	}
	if (ret)
		hash_failed = true;
	return ret;
}

/*
 * The view's LEN events, or a view that holds no history to replay: no
 * events at all, a count of none, or one past the limit.
 */
static void any_view(struct config_evidence *view, bool *holds_events)
{
	bool whole;

	if (whole) {
		view->events = any_bytes(LEN * sizeof(*view->events));
		view->n_events = LEN;
	} else if (view->events) {
		view->events = any_bytes(sizeof(*view->events));
		if (view->n_events <= CONFIG_EVIDENCE_EVENTS_MAX)
			view->n_events = 0;
	}
	*holds_events = whole && LEN;
	history = view;
	memcpy(pcr_now, view->initial_pcr, 32);
	n_extended = 0;
	digest_ready = false;
	initial_asked = false;
	hash_failed = false;
}

/* One boot event, then updates, each sequence number the one before plus 1. */
static bool in_order(const struct config_evidence *view)
{
	const struct config_evidence_event *event = view->events;
	size_t i;

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

static void replayed(void)
{
	struct config_evidence view;
	bool holds_events;
	__u8 out[32];
	int ret;

	any_view(&view, &holds_events);
	ret = replay(&view, out);
	if (!holds_events) {
		__CPROVER_assert(ret == -EINVAL && !n_extended && !digest_ready,
				 "no history, or one past the limit, unread");
		return;
	}
	__CPROVER_assert(!ret == (in_order(&view) && !hash_failed),
			 "replays exactly a history in order");
	__CPROVER_assert(in_order(&view) || hash_failed ||
			 ret == -EKEYREJECTED,
			 "a history out of order is named as such");
	__CPROVER_assert(ret || (n_extended == LEN && same(out, pcr_now)),
			 "the PCR after every event");
}

static void verified(void)
{
	bool holds_events, config_pcr, nvpcr, approved, have_root, certified;
	const __u8 *expected_root = NULL, *nvpcr_value = NULL, *live;
	__u32 quote_mask, reset;
	struct config_evidence view;
	const char *reason = NULL;
	int expected_pcr, ret;
	__u8 pcrs[24][32];

	any_view(&view, &holds_events);
	if (have_root)
		expected_root = any_bytes(32);
	if (certified)
		nvpcr_value = any_bytes(32);
	ret = config_evidence_verify(&view, quote_mask, reset, pcrs,
				     nvpcr_value, expected_root, expected_pcr,
				     &reason);
	__CPROVER_assert(reason, "a reason either way");
	if (!view.present) {
		__CPROVER_assert(ret == (expected_root || expected_pcr >= 0 ?
					 -EKEYREJECTED : 0),
				 "no history passes only when none is expected");
		return;
	}
	config_pcr = view.pcr < 16 && view.pcr != CHAIN_PCR &&
		     view.pcr != CHAIN_PHASE_PCR;
	nvpcr = view.pcr == TPM_CONFIG_NVPCR_INDEX;
	approved = ((config_pcr && (quote_mask >> view.pcr & 1)) ||
		    (nvpcr && nvpcr_value &&
		     same(view.initial_pcr, nvpcr_initial))) &&
		   (expected_pcr < 0 || view.pcr == (__u32)expected_pcr) &&
		   view.reset_count == reset &&
		   !(expected_root && expected_pcr < 0);
	if (!approved) {
		__CPROVER_assert(ret,
				 "refused unless quoted or certified, expected and of this boot");
		return;
	}
	if (!holds_events || !in_order(&view) || hash_failed) {
		__CPROVER_assert(ret, "no history and one out of order refused");
		return;
	}
	__CPROVER_assert(n_extended == LEN, "every event extended");
	live = nvpcr ? nvpcr_value : pcrs[view.pcr];
	__CPROVER_assert(!ret ==
			 (same(live, pcr_now) &&
			  (!expected_root ||
			   same(view.events[LEN - 1].root_hash,
				expected_root))),
			 "passes exactly on its register's replay and the expected last root");
}

void harness(void)
{
	__CPROVER_havoc_slice(nvpcr_initial, sizeof(nvpcr_initial));
	replayed();
	verified();
}
