// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * config_evidence_collect() and collect_event() of util/config_attest.c on
 * every journal of LEN records and every active selection, the journal's
 * reader a stub that hands them over and SHA-256 any result: a history is
 * exported only as this TPM boot's records, in order and ending at the
 * selection, and a refusal returns nothing and leaves nothing allocated.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/config_measure.c"
/* The C converts a __s64 and cuts a __u64 to bytes on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/chain.c"
#pragma CPROVER check pop
#include "../../../util/config_attest.c"

/*
 * Each record is an object of its own, as the reader hands them over one at
 * a time: in one object of 8 KB, a read through a pointer CBMC keeps
 * symbolic, as history()'s last, could be any byte of it.
 */
static const struct config_update_record *journal[LEN + 1], *selection;
static int check_result, read_result;
static __u8 last_digest[32];
static bool hash_failed;

static int any_result(void)
{
	int ret;

	return ret;
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	int ret = any_result();

	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	memcpy(last_digest, out, 32);
	if (ret)
		hash_failed = true;
	return ret;
}

int config_update_check(struct config_update *update,
			struct config_update_record *out)
{
	if (!check_result)
		*out = *selection;
	return check_result;
}

int config_update_events(struct config_update *update,
			 shirudo_config_cb consume, void *ctx)
{
	size_t i;
	int ret;

	for (i = 0; i < LEN; i++) {
		ret = consume(journal[i], ctx);
		if (ret)
			return ret;
	}
	return read_result;
}

static bool same(const __u8 *a, const __u8 *b)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (a[i] != b[i])
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

/* A TPM boot is its reset count: a restart or a resume goes on in it. */
static bool this_boot(const struct config_update_record *record)
{
	return record->reset_count == selection->reset_count;
}

/* On the selection's PCR, from its initial value, a sequence in a __s64. */
static bool agrees(const struct config_update_record *record)
{
	return record->pcr == selection->pcr &&
	       record->sequence <= INT64_MAX &&
	       same(record->initial_pcr, selection->initial_pcr);
}

/*
 * Whether this boot's records are one boot event, then updates in sequence,
 * that end at the selection; *n counts them.
 */
static bool history(size_t *n)
{
	const struct config_update_record *last = NULL;
	size_t i;

	*n = 0;
	for (i = 0; i < LEN; i++) {
		if (!this_boot(journal[i]))
			continue;
		if (!agrees(journal[i]) || !journal[i]->sequence ||
		    journal[i]->kind != (last ? CONFIG_EVENT_UPDATE :
						CONFIG_EVENT_BOOT) ||
		    (last && journal[i]->sequence - last->sequence != 1))
			return false;
		last = journal[i];
		(*n)++;
	}
	return last && last->sequence == selection->sequence &&
	       same(last->target.root_hash, selection->target.root_hash);
}

/*
 * The record of this boot that comes at-th, in the journal's order, so that
 * check_exported() reads events[] at an index CBMC knows.
 */
static const struct config_update_record *this_boot_at(size_t at)
{
	size_t i, seen = 0;

	for (i = 0; i < LEN; i++) {
		if (!this_boot(journal[i]))
			continue;
		if (seen++ == at)
			return journal[i];
	}
	return NULL;
}

static void check_exported(const struct config_evidence *view, size_t n)
{
	const struct config_update_record *record;
	size_t at;

	__CPROVER_assert(view->present && view->pcr == selection->pcr &&
			 view->reset_count == selection->reset_count &&
			 view->restart_count == selection->restart_count &&
			 same(view->initial_pcr, selection->initial_pcr),
			 "the selection's PCR, TPM boot and initial value");
	__CPROVER_assert(view->n_events == n && n <= view->capacity,
			 "this boot's records and no other, inside their room");
	for (at = 0; at < LEN && at < n; at++) {
		record = this_boot_at(at);
		__CPROVER_assert(record &&
				 view->events[at].sequence == record->sequence &&
				 view->events[at].kind == record->kind &&
				 same(view->events[at].root_hash,
				      record->target.root_hash),
				 "each as the journal has it, in its order");
	}
	__CPROVER_assert(same(view->value, last_digest),
			 "the value after the last event");
}

void harness(void)
{
	struct config_update update, *given = NULL;
	struct config_evidence view;
	bool attested, whole;
	size_t i, n;
	int ret;

	for (i = 0; i < LEN; i++)
		journal[i] = any_bytes(sizeof(*journal[i]));
	selection = any_bytes(sizeof(*selection));
	check_result = any_result();
	read_result = any_result();
	if (attested)
		given = &update;
	ret = config_evidence_collect(given, &view);
	if (!given) {
		__CPROVER_assert(!ret && blank(&view),
				 "no config state exports no history");
		return;
	}
	whole = history(&n);
	__CPROVER_assert(!ret == (!check_result && !read_result && whole &&
				  !hash_failed),
			 "exports exactly a checked selection with its history whole");
	if (ret)
		__CPROVER_assert(blank(&view), "a refusal returns nothing");
	else
		check_exported(&view, n);
	config_evidence_clear(&view);
}
