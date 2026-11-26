// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * util/json.c reads back what it writes: every string of LEN bytes the
 * writer takes, the reader takes whole and decodes to the same bytes.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

void harness(void)
{
	char out[6 * LEN + 3], back[LEN + 1];
	struct json_emit e = {};
	struct pctx c = {};
	const char *s;

	s = any_bytes(LEN);
	e.buf = out;
	e.cap = sizeof(out);
	put_string_n(&e, s, LEN, false);
	if (e.err)
		return;
	c.p = out;
	c.end = out + e.len;
	__CPROVER_assert(!parse_string(&c, back, sizeof(back)) && c.p == c.end,
			 "read back whole");
	__CPROVER_assert(!memcmp(back, s, LEN) && !back[LEN],
			 "to the same bytes");
}
