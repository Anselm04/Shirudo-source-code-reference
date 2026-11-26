// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * record_word() of util/attest.c, for every value of up to LEN characters
 * of a target's evidence: it passes only the [a-z_] words a record's type
 * may hold, which the report prints. The evidence's hex fields go through
 * hex_decode_max(), which the hex proof covers.
 */

#include "proof.h"
#include "../../../util/hex.c"
#include "../../../util/attest.c"

static char *any_string(size_t cap)
{
	char *s = any_bytes(cap);

	s[cap - 1] = '\0';
	return s;
}

static void word(void)
{
	char *s = any_string(LEN + 1);
	bool lower = true;
	size_t i;

	for (i = 0; s[i]; i++)
		lower = lower && ((s[i] >= 'a' && s[i] <= 'z') || s[i] == '_');
	__CPROVER_assert(record_word(s) == lower, "[a-z_] and nothing else");
}

void harness(void)
{
	word();
}
