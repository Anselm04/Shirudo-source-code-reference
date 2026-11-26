// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The strict string writer of util/json.c against the model
 * testing/proofs/lean4/Shirudo/JsonString.lean proves the reader inverts
 * for every length: on every string of LEN bytes put_string_n() refuses
 * exactly where write does, and otherwise writes the same bytes.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "json-model.h"

#define OUT_MAX	(6 * LEN + 3)

void harness(void)
{
	struct json_emit e = {};
	__u8 want[OUT_MAX];
	size_t want_len;
	const __u8 *s;
	int model;

	s = any_bytes(LEN);
	e.buf = any_bytes(OUT_MAX);
	e.cap = OUT_MAX;
	put_string_n(&e, (const char *)s, LEN, false);
	model = model_write(s, LEN, want, &want_len);
	__CPROVER_assert(e.err == model, "write's result");
	if (model)
		return;
	__CPROVER_assert(e.len == want_len && !memcmp(e.buf, want, want_len),
			 "and its bytes");
}
