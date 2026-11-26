// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * token_from_body() of util/bpm_oci.c on a token server's answer of up to
 * TEXT_MAX bytes, for every outcome json_parse() may give it: the whole
 * answer goes to json_parse(), the token it takes is the value of
 * "token", else that of "access_token", terminated and fit for a header
 * line, and a refused answer writes no token. And token_from_reply(), on
 * the response buffer curl filled with up to TEXT_MAX bytes of any value:
 * an answer without a body or with a NUL among its bytes gives no token,
 * and any other has all of its bytes parsed. json_parse() itself is held
 * to its contract by the json- proofs.
 */

/* util/malloc.c and util/string.c behind a file that includes their headers. */
#define MALLOC_INTERNAL
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_oci.c"
#include "../../../util/malloc.c"
#include "../../../util/string.c"

#define TEXT_MAX	17
#define OUT_MAX		3
#define FIELDS		2

/* What the model of json_parse() was handed and what it gave. */
static struct {
	bool		called;
	const char	*data;
	size_t		len;
	int		ret;
	bool		seen[FIELDS];
	char		value[FIELDS][OUT_MAX];
} parse;

/*
 * json_parse() as util/json.h promises it: one of its errors or 0, and
 * each declared string field written anywhere within its room and, where
 * a parse that succeeded has seen it, terminated there. A parse that
 * failed promises nothing of what it wrote.
 */
int json_parse(const char *data, size_t len, struct json_field *fields,
	       size_t n_fields)
{
	size_t i, j;
	int ret;

	__CPROVER_assert(n_fields == FIELDS, "the two members declared");
	__CPROVER_assume(ret == 0 || ret == -EINVAL || ret == -E2BIG ||
			 ret == -ENOSPC);
	parse.called = true;
	parse.data = data;
	parse.len = len;
	parse.ret = ret;
	for (i = 0; i < n_fields; i++) {
		char *dst = fields[i].dst;
		bool seen;

		__CPROVER_assert(fields[i].type == JSON_T_STRING &&
				 fields[i].dst_cap <= OUT_MAX,
				 "a string field no larger than out");
		for (j = 0; j < fields[i].dst_cap; j++) {
			char c;

			dst[j] = c;
			parse.value[i][j] = c;
		}
		if (seen && !ret)
			__CPROVER_assume(memchr(dst, '\0', fields[i].dst_cap));
		fields[i].seen = seen;
		parse.seen[i] = seen;
	}
	return ret;
}

static bool header_safe(const char *s)
{
	for (; *s; s++)
		if ((__u8)*s < 0x21 || *s == '\\' || *s == '"' ||
		    (__u8)*s == 0x7f)
			return false;
	return true;
}

/* What every answer the parser saw gives: no token, or the right one. */
static void outcome(int ret, const char *out, const char *was)
{
	const char *member = parse.seen[0] ? parse.value[0] : parse.value[1];

	if (ret) {
		__CPROVER_assert(!memcmp(out, was, OUT_MAX),
				 "a refused answer writes no token");
		return;
	}
	__CPROVER_assert(!parse.ret && (parse.seen[0] || parse.seen[1]),
			 "a token only from an answer parsed whole that has one");
	__CPROVER_assert(memchr(out, '\0', OUT_MAX), "a terminated token");
	__CPROVER_assert(!strcmp(out, member),
			 "the value of token, else that of access_token");
	__CPROVER_assert(header_safe(out),
			 "no blank, control, quote or backslash in the token");
}

static void answer_text(void)
{
	char *body = any_bytes(TEXT_MAX + 1);
	char out[OUT_MAX], was[OUT_MAX];
	int ret;

	__CPROVER_assume(!body[TEXT_MAX]);
	memcpy(was, out, sizeof(out));
	parse.called = false;
	ret = token_from_body(body, out, sizeof(out));
	__CPROVER_assert(parse.called && parse.data == body &&
			 parse.len == strlen(body),
			 "the whole answer parsed");
	outcome(ret, out, was);
}

/* The response as bpm_buffer_append() leaves it: a NUL behind its bytes. */
static void answer_bytes(void)
{
	struct bpm_buffer reply = { .cap = TEXT_MAX + 1 }, none = {};
	char *body = any_bytes(TEXT_MAX + 1);
	char out[OUT_MAX], was[OUT_MAX];
	bool nul = false;
	size_t len, i;
	int ret;

	__CPROVER_assume(len <= TEXT_MAX && !body[len]);
	reply.data = (__u8 *)body;
	reply.len = len;
	for (i = 0; i < len; i++)
		if (!body[i])
			nul = true;
	memcpy(was, out, sizeof(out));
	parse.called = false;
	__CPROVER_assert(token_from_reply(&none, out, sizeof(out)) == -EINVAL &&
			 !memcmp(out, was, sizeof(out)) && !parse.called,
			 "no token from an answer without a body");
	ret = token_from_reply(&reply, out, sizeof(out));
	if (nul) {
		__CPROVER_assert(ret == -EINVAL && !parse.called &&
				 !memcmp(out, was, sizeof(out)),
				 "no token from an answer with a NUL among its bytes");
		return;
	}
	__CPROVER_assert(parse.called && parse.data == body &&
			 parse.len == len,
			 "else every byte of the answer parsed");
	outcome(ret, out, was);
}

void harness(void)
{
	answer_text();
	answer_bytes();
}
