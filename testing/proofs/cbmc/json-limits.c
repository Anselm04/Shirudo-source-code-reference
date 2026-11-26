// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The limits of json_walk() and json_parse() in util/json.c, at the
 * JSON_MAX_BYTES and JSON_MAX_DEPTH proofs.list sets: a longer input and
 * deeper nesting are refused, a callback's error ends the walk at whichever
 * callback, and a declared key takes one value.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

#define DEEP	(JSON_MAX_DEPTH + 1)

struct walk {
	size_t	calls;
	size_t	fail_at;
};

static int called(void *ctx)
{
	struct walk *w = ctx;

	return w->calls++ == w->fail_at ? -EIO : 0;
}

static int on_open(void *ctx, bool array)
{
	return called(ctx);
}

static int on_close(void *ctx, bool array)
{
	return called(ctx);
}

static int on_string(void *ctx, const char *s)
{
	return called(ctx);
}

static int on_number(void *ctx, const char *text, size_t len, bool integer)
{
	return called(ctx);
}

static int on_literal(void *ctx, int value)
{
	return called(ctx);
}

static const struct json_visitor visitor = {
	.open = on_open,
	.close = on_close,
	.key = on_string,
	.string = on_string,
	.number = on_number,
	.literal = on_literal,
};

static void stopped(const char *doc, size_t calls)
{
	struct walk w = {};
	size_t fail_at;
	int ret;

	__CPROVER_assume(fail_at <= calls);
	w.fail_at = fail_at;
	ret = json_walk(doc, strlen(doc), &visitor, &w);
	__CPROVER_assert(ret == (fail_at < calls ? -EIO : 0) &&
			 w.calls == min(fail_at + 1, calls),
			 "a callback's error ends the walk");
}

static void nested(size_t depth)
{
	struct walk w = { .fail_at = SIZE_MAX };
	char doc[2 * DEEP];
	size_t i;

	for (i = 0; i < depth; i++) {
		doc[i] = '[';
		doc[2 * depth - 1 - i] = ']';
	}
	__CPROVER_assert(json_walk(doc, 2 * depth, &visitor, &w) ==
			 (depth > JSON_MAX_DEPTH ? -E2BIG : 0),
			 "JSON_MAX_DEPTH levels at most");
}

/* A declared key named twice, null or not, as json.h says. */
static void twice(void)
{
	struct json_field f = { "k", JSON_T_INT, NULL, 0, 0, NULL, 0 };
	__s64 num = 0;

	f.dst = &num;
	__CPROVER_assert(json_parse("{\"k\":1,\"k\":2}", 13, &f, 1) == -EINVAL,
			 "a second value refused");
	__CPROVER_assert(json_parse("{\"k\":1,\"k\":null}", 16, &f, 1) ==
			 -EINVAL, "a null after a value refused");
	__CPROVER_assert(json_parse("{\"k\":null,\"k\":2}", 16, &f, 1) ==
			 -EINVAL, "a value after null refused");
	__CPROVER_assert(!json_parse("{\"k\":null}", 10, &f, 1) && !f.seen,
			 "null alone gives no value");
	__CPROVER_assert(!json_parse("{}", 2, &f, 1) && !f.seen,
			 "seen reset per document");
}

void harness(void)
{
	struct walk w = { .fail_at = SIZE_MAX };
	struct json_field f = {};
	char *data;

	data = any_bytes(JSON_MAX_BYTES + 1);
	__CPROVER_assert(json_walk(data, JSON_MAX_BYTES + 1, &visitor, &w) ==
			 -E2BIG && !w.calls, "past JSON_MAX_BYTES unread");
	__CPROVER_assert(json_parse(data, JSON_MAX_BYTES + 1, &f, 1) ==
			 -E2BIG, "a document too");
	__CPROVER_assert(json_walk(data, 1, NULL, NULL) == -EINVAL,
			 "a visitor needed");
	stopped("{\"\":1}", 4);
	stopped("[\"\"]", 3);
	stopped("[true]", 3);
	nested(JSON_MAX_DEPTH);
	nested(DEEP);
	twice();
}
