// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * event_follows() and same_event() of util/config_update.c, on which every
 * check of the config activation journal rests, against Follows and the
 * equality of events in the Lean model Shirudo.ConfigActivation, for every
 * record record_decode() accepts and the zeroed one before the first line:
 * a first event follows exactly when it is boot event 1, a later one when
 * its sequence is the next and it is a boot event of another TPM boot or
 * an update of the same TPM boot on the same PCR from the same initial
 * value, and a refusal is EUCLEAN. Two events are the same exactly when
 * TPM boot, sequence, PCR, kind, initial value and root agree. A TPM
 * boot is the model's B, the reset count: the restart count is no part
 * of it.
 */

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/config_update.c"

static bool bytes_equal(const __u8 *a, const __u8 *b)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

static void decoded(const struct config_update_record *r)
{
	__CPROVER_assume(r->sequence > 0 && r->sequence <= INT64_MAX);
	__CPROVER_assume(r->kind == CONFIG_EVENT_BOOT ||
			 r->kind == CONFIG_EVENT_UPDATE);
	__CPROVER_assume(r->pcr < 16);
}

static void follows(void)
{
	struct config_update_record previous, record;
	bool have, boot, model;
	int ret;

	decoded(&record);
	if (have)
		decoded(&previous);
	else
		memset(&previous, 0, sizeof(previous));
	ret = event_follows(&previous, &record);
	boot = record.kind == CONFIG_EVENT_BOOT;
	if (!have)
		model = record.sequence == 1 && boot;
	else if (previous.reset_count == record.reset_count)
		model = record.sequence == previous.sequence + 1 && !boot &&
			previous.pcr == record.pcr &&
			bytes_equal(previous.initial_pcr, record.initial_pcr);
	else
		model = record.sequence == previous.sequence + 1 && boot;
	__CPROVER_assert(!ret == model, "event_follows() accepts what Follows does");
	__CPROVER_assert(!ret || ret == -EUCLEAN, "and refuses with EUCLEAN");
}

static void same(void)
{
	struct config_update_record a, b;

	__CPROVER_assert(same_event(&a, &b) ==
			 (a.reset_count == b.reset_count &&
			  a.sequence == b.sequence && a.pcr == b.pcr &&
			  a.kind == b.kind &&
			  bytes_equal(a.initial_pcr, b.initial_pcr) &&
			  bytes_equal(a.target.root_hash, b.target.root_hash)),
			 "same_event() is the equality of the modelled fields");
}

void harness(void)
{
	follows();
	same();
}
