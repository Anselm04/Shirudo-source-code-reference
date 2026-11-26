// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The string reader of util/json.c against the model
 * testing/proofs/lean4/Shirudo/JsonString.lean proves inverts the writer
 * for every length: on every input of LEN bytes, every buffer of up to
 * LEN + 1 bytes or none, and a JSON_MAX_STRING_BYTES the input can pass,
 * parse_string() returns what readString returns, ends where it does and
 * decodes the same bytes.
 */

#define JSON_MAX_STRING_BYTES	3

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "json-model.h"

void harness(void)
{
	size_t cap, k = 0, end = 0;
	char buf[LEN + 1];
	__u8 want[LEN + 1];
	struct pctx c = {};
	struct room r;
	const char *s;
	bool discard;
	int ret, model;

	s = any_bytes(LEN);
	c.p = s;
	c.end = s + LEN;
	__CPROVER_assume(cap <= sizeof(buf));
	r.dst = !discard;
	r.cap = cap;
	r.max = JSON_MAX_STRING_BYTES;
	ret = parse_string(&c, discard ? NULL : buf, cap);
	model = model_read((const __u8 *)s, LEN, &r, want, &k, &end);
	__CPROVER_assert(ret == model, "readString's result");
	if (ret)
		return;
	__CPROVER_assert(c.p == s + end, "ending where it does");
	if (!discard)
		__CPROVER_assert(!memcmp(buf, want, k) && !buf[k],
				 "with the same bytes");
}
