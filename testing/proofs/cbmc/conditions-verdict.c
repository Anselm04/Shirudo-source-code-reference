// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * status_verdict() and status_reason() of util/conditions.c on every input:
 * the verdict is the first of its order that applies, tampered exactly when
 * a cause holds, whatever else the input says, and the reason is that of
 * the first cause in the documented order.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/conditions.c"
#include "../../../util/string.c"

#define UNREACH_MAX	9

enum verdict {
	UNREACHABLE,
	UNPARSEABLE,
	TAMPERED,
	LSM_OFF,
	INIT_PENDING,
	REBOOT_PENDING,
	DEGRADED,
	OK,
};

static const char *const verdict_word[] = {
	[UNREACHABLE]		= "unreachable",
	[UNPARSEABLE]		= "unparseable",
	[TAMPERED]		= "tampered",
	[LSM_OFF]		= "lsm-off",
	[INIT_PENDING]		= "init-pending",
	[REBOOT_PENDING]	= "reboot-pending",
	[DEGRADED]		= "degraded",
	[OK]			= "ok",
};

static const char *const verdict_reason[] = {
	[UNPARSEABLE]		= "status JSON unparseable",
	[LSM_OFF]		= "LSM not attached, enforcement off",
	[INIT_PENDING]		= ".bpf keyring absent before init",
	[REBOOT_PENDING]	= "a config activation is pending until the next reboot",
	[OK]			= "",
};

/* What makes a host tampered, in the order its reason is taken from. */
enum cause {
	REGISTER_DIFFERS,
	XDP_ARCHIVE_CHANGED,
	LINK_LOST,
	PIN_UNMEASURED,
	RECORDS_DIFFER,
	CONFIG_UNVERIFIED,
	BPF_KEYRING_GONE,
	BPF_KEYRING_SWAPPED,
	DMV_KEYRING_GONE,
	DMV_KEYRING_SWAPPED,
	LINK_UNFROZEN,
	CONFIG_KEY_GONE,
	NR_CAUSES,
};

static const char *const cause_reason[NR_CAUSES] = {
	[REGISTER_DIFFERS]	= "live register differs from the eventlog replay",
	[XDP_ARCHIVE_CHANGED]	= "the archive of a loaded XDP upatch differs from what was loaded",
	[LINK_LOST]		= "a loaded upatch is missing a link or its archive",
	[PIN_UNMEASURED]	= "a upatch is pinned or archived without a record of this boot",
	[RECORDS_DIFFER]	= "this boot's records do not fold to the measurement register",
	[CONFIG_UNVERIFIED]	= "the selected config cannot be verified against its records",
	[BPF_KEYRING_GONE]	= "the keyring init froze is gone",
	[BPF_KEYRING_SWAPPED]	= "keyring serial swap detected",
	[DMV_KEYRING_GONE]	= "the dm-verity keyring init froze is gone",
	[DMV_KEYRING_SWAPPED]	= "dm-verity keyring serial swap detected",
	[LINK_UNFROZEN]		= "a keyring holds a link init did not freeze",
	[CONFIG_KEY_GONE]	= "the config key init froze is gone",
};

static bool cause_holds(const struct conditions_input *in, enum cause cause)
{
	switch (cause) {
	case REGISTER_DIFFERS:
		return in->cm_seen && !in->chain_matches;
	case XDP_ARCHIVE_CHANGED:
		return in->xdp_tampered;
	case LINK_LOST:
		return in->links_lost;
	case PIN_UNMEASURED:
		return in->pins_unmeasured;
	case RECORDS_DIFFER:
		return in->pins_rc == -EBADMSG;
	case CONFIG_UNVERIFIED:
		return in->config_seen && in->config_state &&
		       in->config_state != -EINPROGRESS;
	case BPF_KEYRING_GONE:
		return in->ksp_seen && !in->keyring_present;
	case BPF_KEYRING_SWAPPED:
		return in->ksm_seen && !in->keyring_serial_matches;
	case DMV_KEYRING_GONE:
		return in->dmvp_seen && !in->dmv_present;
	case DMV_KEYRING_SWAPPED:
		return in->dmvm_seen && !in->dmv_serial_matches;
	case LINK_UNFROZEN:
		return in->bpf_unfrozen || in->dmv_unfrozen;
	case CONFIG_KEY_GONE:
		return in->dmv_key_missing;
	default:
		return false;
	}
}

/* NR_CAUSES when none holds. */
static enum cause first_cause(const struct conditions_input *in)
{
	enum cause cause;

	for (cause = 0; cause < NR_CAUSES; cause++)
		if (cause_holds(in, cause))
			break;
	return cause;
}

static bool verdict_applies(const struct conditions_input *in, enum verdict v)
{
	switch (v) {
	case UNREACHABLE:
		return !in->reachable;
	case UNPARSEABLE:
		return !in->parsed;
	case TAMPERED:
		return first_cause(in) != NR_CAUSES;
	case LSM_OFF:
		return !in->lsm_attached;
	case INIT_PENDING:
		return !in->keyring_present;
	case REBOOT_PENDING:
		return in->config_seen && in->config_state == -EINPROGRESS;
	case DEGRADED:
		return !in->chain_seen || in->xdp_uncovered;
	default:
		return true;
	}
}

static const char *reason_of(const struct conditions_input *in, enum verdict v)
{
	switch (v) {
	case UNREACHABLE:
		return in->unreach ? in->unreach : "";
	case TAMPERED:
		return cause_reason[first_cause(in)];
	case DEGRADED:
		if (in->chain_seen)
			return "a device an XDP upatch selects does not run it";
		return in->tpm_reachable ? "no register bound this boot" :
		       "no TPM answered";
	default:
		return verdict_reason[v];
	}
}

void harness(void)
{
	struct conditions_input in;
	const char *verdict;
	enum verdict v = 0;
	bool said;

	if (said) {
		char *unreach = any_bytes(UNREACH_MAX + 1);

		__CPROVER_assume(!unreach[UNREACH_MAX]);
		in.unreach = unreach;
	} else {
		in.unreach = NULL;
	}
	verdict = status_verdict(&in);
	while (!verdict_applies(&in, v))
		v++;
	__CPROVER_assert(!strcmp(verdict, verdict_word[v]),
			 "the first verdict of the order that applies");
	__CPROVER_assert(!strcmp(verdict, "tampered") ==
			 (in.reachable && in.parsed &&
			  first_cause(&in) != NR_CAUSES),
			 "tampered exactly when the host answered and a cause holds");
	__CPROVER_assert(!strcmp(status_reason(&in), reason_of(&in, v)),
			 "the reason of the verdict and of the first cause");
}
