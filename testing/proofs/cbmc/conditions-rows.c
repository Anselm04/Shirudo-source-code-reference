// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * conditions() of util/conditions.c on every input, into room for LEN rows:
 * the rows of the report in order, each the first state of the reference
 * that applies, the worst first but for the keyring, formatted from that
 * state's numbers and names, and none an ALERT under a verdict that does
 * not say so.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL
/* A detail is copied from the literal the input picks. */
#define PROOF_MEMCPY_BYTEWISE

/*
 * The digits and names proof.h's vsnprintf() writes put what follows them
 * at an offset CBMC keeps symbolic, which two rows already run out of
 * memory on. The one below keeps each argument for the proof to compare
 * and writes one byte in its place; conditions-detail has the other.
 */
#include <stdio.h>
#define vsnprintf	vsnprintf_in_full
#include "proof.h"
#undef vsnprintf

#include "../../../util/conditions.c"
#include "../../../util/string.c"

/* The largest errno the kernel has: a status code is 0 or one, negated. */
#define ERRNO_MAX	4095

/* What a conversion took: a string and its precision, or a number. */
struct taken {
	const char *string;
	size_t cut;
	__s64 number;
};

/* Two to a text: no detail has more, and a text then knows its own. */
static struct taken taken[CONDITIONS_MAX][2];
static size_t n_texts;

/* What the '#' and the '*' of a detail stand for, in their order. */
struct args {
	__s64 number[2];
	const char *string;
	size_t cut;
};

static const char *const row_type[CONDITIONS_MAX] = {
	"LsmAttached", "KeyringSealed", "ChainIntact", "UpatchesMeasured",
	"TpmMeasured", "ConfigActive", "XdpCovered",
};

static size_t put(char *buf, size_t size, size_t n, char c)
{
	if (n + 1 < size)
		buf[n] = c;
	return n + 1;
}

/*
 * The text of a format, each conversion one byte in it that says where
 * what it took is kept.
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	size_t n = 0, text = n_texts++, i = 0;

	__CPROVER_assert(text < ARRAY_SIZE(taken), "a text for each row");
	for (; *fmt; fmt++) {
		struct taken t = {};

		if (*fmt != '%') {
			n = put(buf, size, n, *fmt);
			continue;
		}
		if (*++fmt == '.')
			for (fmt++; *fmt >= '0' && *fmt <= '9'; fmt++)
				t.cut = t.cut * 10 + (size_t)(*fmt - '0');
		if (*fmt == 's') {
			t.string = va_arg(ap, const char *);
			__CPROVER_assert(t.string, "a string for %s");
		} else if (fmt[0] == 'l' && fmt[1] == 'l') {
			t.number = va_arg(ap, __s64);
			fmt += 2;
		} else {
			t.number = va_arg(ap, int);
		}
		__CPROVER_assert((t.string || (*fmt == 'd' && !t.cut)) &&
				 i < ARRAY_SIZE(taken[text]),
				 "a conversion this vsnprintf() has");
		taken[text][i++] = t;
		n = put(buf, size, n, (char)(2 * text + i));
	}
	if (size)
		buf[min(n, size - 1)] = '\0';
	return (int)n;
}

/* A text of its own for every error, where CBMC's has one for all. */
char *strerror(int errnum)
{
	static char text[ERRNO_MAX + 1];

	__CPROVER_assert(errnum > 0 && errnum <= ERRNO_MAX, "an errno");
	return text + errnum;
}

/*
 * Whether s is the detail, its '#' and '*' what took the args given. A
 * string is told by its address: every name and error has its own, and
 * CBMC gives equal literals one, without which this would fail, not hold.
 */
static bool spells(const char *s, const char *detail, const struct args *args)
{
	size_t numbers = 0;

	for (; *detail; detail++, s++) {
		const struct taken *t;

		if (*detail != '#' && *detail != '*') {
			if (*s != *detail)
				return false;
			continue;
		}
		if (!*s || *s > 2 * n_texts)
			return false;
		t = &taken[(*s - 1) / 2][(*s - 1) % 2];
		if (*detail == '#') {
			if (t->string || t->number != args->number[numbers++])
				return false;
		} else if (t->string != args->string || t->cut != args->cut) {
			return false;
		}
	}
	return !*s;
}

static bool row_is(const struct condition *c, const char *status,
		   const char *detail, struct args args)
{
	return !strcmp(c->status, status) && spells(c->detail, detail, &args);
}

#define OK(detail, ...)		row_is(c, "OK", detail, (struct args){ __VA_ARGS__ })
#define WARN(detail, ...)	row_is(c, "WARN", detail, (struct args){ __VA_ARGS__ })
#define ALERT(detail, ...)	row_is(c, "ALERT", detail, (struct args){ __VA_ARGS__ })

static const char *or_unknown(const char *names)
{
	return names ? names : "?";
}

static bool lsm_row(const struct conditions_input *in,
		    const struct condition *c)
{
	if (!in->lsm_attached)
		return ALERT("lsm/bpf link absent, enforcement off");
	return OK("lsm/bpf link present and pinned");
}

static bool keyring_row(const struct conditions_input *in,
			const struct condition *c)
{
	if (in->ksp_seen && !in->keyring_present)
		return ALERT("pinned serial #, the .bpf keyring is gone",
			     .number = { in->keyring_serial_pinned });
	if (!in->keyring_present)
		return WARN(".bpf keyring absent before init");
	if (in->ksm_seen && !in->keyring_serial_matches)
		return ALERT("pinned serial #, live serial #: swapped",
			     .number = { in->keyring_serial_pinned,
					 in->keyring_serial });
	if (in->bpf_unfrozen)
		return ALERT("the BPF keyring holds # link* init did not freeze",
			     .number = { in->bpf_unfrozen },
			     .string = in->bpf_unfrozen == 1 ? "" : "s");
	if (in->dmvp_seen && !in->dmv_present)
		return ALERT("dm-verity pinned serial #, the dm-verity keyring is gone",
			     .number = { in->dmv_serial_pinned });
	if (in->dmvm_seen && !in->dmv_serial_matches)
		return ALERT("dm-verity pinned serial #, live serial #: swapped",
			     .number = { in->dmv_serial_pinned, in->dmv_serial });
	if (in->dmv_unfrozen)
		return ALERT("the dm-verity keyring holds # link* init did not freeze",
			     .number = { in->dmv_unfrozen },
			     .string = in->dmv_unfrozen == 1 ? "" : "s");
	if (in->dmv_key_missing)
		return ALERT("a config key init froze is gone from the dm-verity keyring");
	if (in->ksp_seen && in->dmvp_seen)
		return OK("bpf serial #, dm-verity serial #, pins match",
			  .number = { in->keyring_serial, in->dmv_serial });
	return OK("bpf serial #, *", .number = { in->keyring_serial },
		  .string = in->ksp_seen ? "pin matches" : "no pin recorded");
}

static bool chain_row(const struct conditions_input *in,
		      const struct condition *c)
{
	if (in->cm_seen && !in->chain_matches)
		return ALERT("live register differs from the eventlog replay");
	if (!in->chain_seen && !in->tpm_reachable)
		return WARN("no TPM answered, no register to replay");
	if (!in->chain_seen)
		return WARN("no register bound this boot (init incomplete)");
	if (!in->cm_seen)
		return WARN("chain present, replay not evaluated");
	return OK("live register equals the eventlog replay");
}

static bool upatches_row(const struct conditions_input *in,
			 const struct condition *c)
{
	if (in->xdp_tampered)
		return ALERT("# XDP archives differ from the loaded payload: *",
			     .number = { in->xdp_tampered },
			     .string = or_unknown(in->xdp_tampered_detail));
	if (in->links_lost)
		return ALERT("# upatches are missing a link or their archive: *",
			     .number = { in->links_lost },
			     .string = or_unknown(in->links_lost_detail));
	if (in->pins_unmeasured)
		return ALERT("# pinned or archived without a record of this boot: *",
			     .number = { in->pins_unmeasured },
			     .string = or_unknown(in->pins_detail));
	if (in->pins_rc == -ENOENT)
		return WARN("no record of this boot to check the pins against");
	if (in->pins_rc == -EBADMSG)
		return ALERT("this boot's records do not fold to the measurement register");
	if (in->pins_rc)
		return WARN("pins not checked against the records: *",
			    .string = strerror(-in->pins_rc));
	if (in->checks_rc)
		return WARN("links or archives not checked: *",
			    .string = strerror(-in->checks_rc));
	return OK("every pinned or archived upatch is in this boot's records");
}

static bool tpm_row(const struct conditions_input *in,
		    const struct condition *c)
{
	if (in->chain_seen)
		return OK("NV index * readable",
			  .string = or_unknown(in->nv_index));
	if (in->tpm_reachable)
		return WARN("NV index * not bound this boot",
			    .string = or_unknown(in->nv_index));
	return WARN("no TPM answered");
}

static bool config_row(const struct conditions_input *in,
		       const struct condition *c)
{
	if (!in->config_seen)
		return WARN("no config activation state before init");
	if (in->config_state == -EINPROGRESS)
		return WARN("the activation of config *.. is pending until the next reboot",
			    .string = or_unknown(in->config_root), .cut = 12);
	if (in->config_state == -ESTALE)
		return ALERT("the config activation record does not belong to this TPM boot");
	if (in->config_state == -EKEYREJECTED)
		return ALERT("the mounted config does not match the selected root");
	if (in->config_state)
		return ALERT("the config PCR, activation records and mounted config disagree");
	return OK("config *.. is active",
		  .string = or_unknown(in->config_root), .cut = 12);
}

static bool xdp_row(const struct conditions_input *in,
		    const struct condition *c)
{
	if (in->xdp_uncovered)
		return WARN("# selected devices run without their XDP upatch: *",
			    .number = { in->xdp_uncovered },
			    .string = or_unknown(in->xdp_uncovered_detail));
	if (in->xdp_coverage_rc == -EXDEV)
		return WARN("XDP coverage not checked: *",
			    .string = "not in the initial network namespace");
	if (in->xdp_coverage_rc)
		return WARN("XDP coverage not checked: *",
			    .string = strerror(-in->xdp_coverage_rc));
	return OK("every device an XDP upatch selects runs it");
}

static bool (*const row_holds[CONDITIONS_MAX])(const struct conditions_input *,
						const struct condition *) = {
	lsm_row, keyring_row, chain_row, upatches_row, tpm_row, config_row,
	xdp_row,
};

/* conditions() hands a name on and reads none: its address is all of it. */
static const char *name_or_none(void)
{
	bool named;

	return named ? any_bytes(1) : NULL;
}

static bool status_code(int rc)
{
	return rc <= 0 && rc >= -ERRNO_MAX;
}

/* The LSM's row alerts under lsm-off too. */
static bool verdict_says(const char *verdict, size_t row)
{
	return !strcmp(verdict, "unreachable") ||
	       !strcmp(verdict, "unparseable") ||
	       !strcmp(verdict, "tampered") ||
	       (!row && !strcmp(verdict, "lsm-off"));
}

void harness(void)
{
	struct condition c[LEN ? LEN : 1], spare;
	size_t rows = min(LEN, CONDITIONS_MAX);
	struct conditions_input in;
	const char *verdict;
	size_t n, i, k;

	in.nv_index = name_or_none();
	in.config_root = name_or_none();
	in.pins_detail = name_or_none();
	in.xdp_tampered_detail = name_or_none();
	in.links_lost_detail = name_or_none();
	in.xdp_uncovered_detail = name_or_none();
	__CPROVER_assume(status_code(in.pins_rc) && status_code(in.checks_rc) &&
			 status_code(in.xdp_coverage_rc));
	__CPROVER_assume(in.chain_seen || !in.cm_seen);
	__CPROVER_assume(!in.pins_rc || !in.pins_unmeasured);
	verdict = status_verdict(&in);

	if (rows < ARRAY_SIZE(c))
		spare = c[rows];
	n = conditions(&in, c, LEN);
	__CPROVER_assert(n == rows,
			 "as many rows as there is room for, seven at most");
	for (i = 0; i < n; i++)
		__CPROVER_assert(!strcmp(c[i].type, row_type[i]),
				 "the rows in the order of the report");
	__CPROVER_assume(k < sizeof(spare.detail));
	if (rows < ARRAY_SIZE(c))
		__CPROVER_assert(c[rows].type == spare.type &&
				 c[rows].status == spare.status &&
				 c[rows].detail[k] == spare.detail[k],
				 "nothing written behind the last row");
	conditions_print(c, n);

	/* Less room changes which rows are written, not what one says. */
	if (n < CONDITIONS_MAX)
		return;
	for (i = 0; i < n; i++) {
		__CPROVER_assert(row_holds[i](&in, &c[i]),
				 "the first state of the row that applies");
		__CPROVER_assert(strcmp(c[i].status, "ALERT") ||
				 verdict_says(verdict, i),
				 "no ALERT under a verdict that does not say so");
	}
}
