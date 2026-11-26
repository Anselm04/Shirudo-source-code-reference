// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The output buffer of util/json.c for every text of LEN bytes written in
 * two calls: the caller's buffer and the emitter's growing one, which may
 * fail to grow, hold the text when it fits and its longest prefix when it
 * does not, with -ENOSPC, -E2BIG past max or -ENOMEM, and stay so.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

#define CAP_MAX	(LEN + 3)

void harness(void)
{
	struct json_emit e = {};
	size_t cut = LEN / 2, cap, max, i;
	bool grows;
	char *t;

	t = any_bytes(LEN);
	__CPROVER_assume(cap <= CAP_MAX && max <= CAP_MAX);
	if (grows) {
		__CPROVER_assume(max && cap <= max);
		e.buf = cap ? xmalloc(cap) : NULL;
		__CPROVER_assume(!cap || e.buf);
		e.max = max;
	} else {
		e.buf = cap ? any_bytes(cap) : NULL;
	}
	e.cap = cap;
	e.value_pending = true;
	json_raw_value(&e, t, cut);
	e.value_pending = true;
	json_raw_value(&e, t + cut, LEN - cut);
	__CPROVER_assert(e.cap >= cap && e.cap <= (grows ? max : cap),
			 "a buffer grown up to max alone");
	__CPROVER_assert(!e.err || e.err == (grows ? -E2BIG : -ENOSPC) ||
			 (grows && e.err == -ENOMEM),
			 "-ENOSPC, -E2BIG or -ENOMEM");
	__CPROVER_assert(e.err == -ENOMEM ||
			 !e.err == (!LEN || LEN + 1 <= (grows ? max : cap)),
			 "the text fails only when it does not fit");
	__CPROVER_assert(e.len == (e.err ? (e.cap ? e.cap - 1 : 0) : LEN),
			 "the whole text or a buffer filled to the end");
	__CPROVER_assert(!e.len || e.len < e.cap, "inside the buffer");
	for (i = 0; i < e.len; i++)
		__CPROVER_assert(e.buf[i] == t[i], "a prefix of the text");
	__CPROVER_assert(!e.len || !e.buf[e.len], "terminated");
	cap = e.cap;
	cut = e.len;
	if (!e.err)
		return;
	e.value_pending = true;
	json_raw_value(&e, t, LEN);
	__CPROVER_assert(e.len == cut && e.cap == cap, "an error stays");
}
