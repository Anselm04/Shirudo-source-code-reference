// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * measured_event() and measured_holds() of util/measured.c against the fold
 * of testing/proofs/lean4/Shirudo/UpatchLoad.lean: after every sequence of
 * up to EVENTS init, load and unload records over two names and two
 * payloads, the set holds a name with a payload exactly when the model's
 * fold maps the name to it, and never with the empty payload of an unread
 * xattr.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/measured.c"

#define EVENTS		6	/* init records first make every shorter sequence */
#define NAMES		2
#define PAYLOADS	2

static const char *const names[NAMES] = { "a", "b" };
static const char *const payloads[PAYLOADS] = { "p0", "p1" };

void harness(void)
{
	struct measured_entry entries[NAMES];
	struct measured_set s = { .entries = entries, .n = 0 };
	int model[NAMES];
	__u32 i, k, p;

	for (k = 0; k < NAMES; k++)
		model[k] = -1;
	for (i = 0; i < EVENTS; i++) {
		__u32 kind, n, q;
		int ret;

		__CPROVER_assume(kind < 3 && n < NAMES && q < PAYLOADS);
		if (kind == 0) {
			ret = measured_event(EVENTLOG_UPATCH_INIT, NULL, NULL, &s);
			for (k = 0; k < NAMES; k++)
				model[k] = -1;
		} else if (kind == 1) {
			ret = measured_event(EVENTLOG_UPATCH_LOAD, names[n],
					     payloads[q], &s);
			model[n] = (int)q;
		} else {
			ret = measured_event(EVENTLOG_UPATCH_UNLOAD, names[n],
					     payloads[q], &s);
			model[n] = -1;
		}
		__CPROVER_assert(ret == 0, "every record folds");
		__CPROVER_assert(s.n <= NAMES, "one entry per name");
	}
	for (k = 0; k < NAMES; k++) {
		for (p = 0; p < PAYLOADS; p++)
			__CPROVER_assert(measured_holds(&s, names[k], payloads[p]) ==
					 (model[k] == (int)p),
					 "held exactly as the model's fold maps it");
		__CPROVER_assert(!measured_holds(&s, names[k], ""),
				 "never held without an xattr");
	}
}
