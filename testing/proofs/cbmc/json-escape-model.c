// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The \u escapes of util/json.c against the reader of
 * testing/proofs/lean4/Shirudo/JsonString.lean, for every pair of code
 * units spelled in either case and every buffer of up to 8 bytes or none:
 * parse_string() returns what readString returns, ends where it does and
 * decodes the same bytes, a surrogate pair, \u0000 and a lone surrogate
 * included.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "json-model.h"

static void spell(char *out, __u16 cu)
{
	int i;

	out[0] = '\\';
	out[1] = 'u';
	for (i = 0; i < 4; i++) {
		__u8 d = cu >> (12 - 4 * i) & 15;
		bool upper;

		out[2 + i] = d < 10 ? '0' + d : (upper ? 'A' : 'a') + d - 10;
	}
}

void harness(void)
{
	size_t cap, k = 0, end = 0;
	struct pctx c = {};
	__u8 want[8];
	struct room r;
	char text[14];
	char buf[8];
	__u16 hi, lo;
	bool discard;
	int ret, model;

	text[0] = '"';
	spell(text + 1, hi);
	spell(text + 7, lo);
	text[13] = '"';
	c.p = text;
	c.end = text + sizeof(text);
	__CPROVER_assume(cap <= sizeof(buf));
	r.dst = !discard;
	r.cap = cap;
	r.max = JSON_MAX_STRING_BYTES;
	ret = parse_string(&c, discard ? NULL : buf, cap);
	model = model_read((const __u8 *)text, sizeof(text), &r, want, &k,
			   &end);
	__CPROVER_assert(ret == model, "readString's result");
	if (ret)
		return;
	__CPROVER_assert(c.p == text + end, "ending where it does");
	if (!discard)
		__CPROVER_assert(!memcmp(buf, want, k) && !buf[k],
				 "with the same bytes");
}
