// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The report attest verify prints on a target's evidence, as text and as
 * JSON, which must give the same exit status, checks and verdict.
 */

#include "fuzz.h"

#include "../../builtin-attest.c"

#define NONCE_HEX	"0102030405060708090a0b0c0d0e0f10"

/* What a report says: its exit status, its checks and its verdict. */
struct verdict {
	int		status;
	size_t		checks;
	const char	*verdict;
	bool		in_result;
	bool		in_verdict;
};

/* attest verify reads no image. */
struct config_update *image_update_context(void)
{
	abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fuzz_output_capture();
	return 0;
}

static bool line_is_check(const char *line, size_t len)
{
	static const char *const marks[] = {
		"  OK    ", "  FAIL  ", "  NOTE  ",
	};

	for (size_t i = 0; i < ARRAY_SIZE(marks); i++)
		if (len > strlen(marks[i]) &&
		    !memcmp(line, marks[i], strlen(marks[i])))
			return true;
	return false;
}

static void text_verdict(const char *s, size_t len, struct verdict *v)
{
	const char *line = s, *end = s + len, *nl;
	size_t n;

	for (; line < end; line = nl + 1) {
		nl = memchr(line, '\n', (size_t)(end - line));
		if (!nl)
			nl = end;
		n = (size_t)(nl - line);
		if (line_is_check(line, n))
			v->checks++;
		else if (span_equals(line, n, "verdict: ok"))
			v->verdict = "ok";
		else if (span_equals(line, n, "verdict: fail"))
			v->verdict = "fail";
	}
}

static int on_key(void *ctx, const char *key)
{
	struct verdict *v = ctx;

	v->in_result = !strcmp(key, "result");
	v->in_verdict = !strcmp(key, "verdict");
	return 0;
}

static int on_string(void *ctx, const char *s)
{
	struct verdict *v = ctx;

	if (v->in_result)
		v->checks++;
	if (v->in_verdict)
		v->verdict = !strcmp(s, "ok") ? "ok" :
			     !strcmp(s, "fail") ? "fail" : "?";
	v->in_result = false;
	v->in_verdict = false;
	return 0;
}

static void json_verdict(const char *s, size_t len, struct verdict *v)
{
	static const struct json_visitor visit = {
		.key = on_key,
		.string = on_string,
	};

	if (len && json_walk(s, len - 1, &visit, v))
		abort();
}

/*
 * A document attest_verify() cannot read gets its partial report in text
 * and nothing in JSON; any other gets both, the same.
 */
static bool verdicts_agree(const struct verdict *text,
			   const struct verdict *json)
{
	if (text->status != json->status)
		return false;
	if (!text->verdict)
		return !json->verdict && !json->checks;
	return text->checks == json->checks && json->verdict &&
	       !strcmp(text->verdict, json->verdict);
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct verdict text = {}, json = {};
	const char *out;
	char path[64];
	size_t len;
	int fd;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	text.status = fuzz_run(cmd_attest_verify, "attest", "verify",
			       "--evidence", path, "--nonce", NONCE_HEX,
			       "--allow-runtime-events", NULL);
	out = fuzz_output(&len);
	text_verdict(out, len, &text);
	json.status = fuzz_run(cmd_attest_verify, "attest", "verify",
			       "--evidence", path, "--nonce", NONCE_HEX,
			       "--allow-runtime-events", "--json", NULL);
	out = fuzz_output(&len);
	json_verdict(out, len, &json);
	if (!verdicts_agree(&text, &json))
		abort();
	close(fd);
	return 0;
}
