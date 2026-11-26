// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>

#include <shirudo/string.h>

#include "malloc.h"
#include "report.h"
#include "unit.h"

#define FFFD	"\\ufffd"

static void a_refusal_is_one_document(void)
{
	struct op_report r = {
		.op = "upatch_load",
		.phase = "parse",
		.err = EINVAL,
		.category = "parser_rejected",
		.message = "unsafe upatch name",
		.path = "a.upatch",
		.name = "a",
	};
	size_t cap;
	char *doc;

	ASSERT_EQ(report_encode(&r, "7.4.0", &doc, &cap), 0);
	EXPECT_STREQ(doc,
		     "{\"schema\":1,\"result\":\"failed\",\"op\":\"upatch_load\","
		     "\"phase\":\"parse\",\"errno\":22,\"errno_name\":\"EINVAL\","
		     "\"category\":\"parser_rejected\","
		     "\"message\":\"unsafe upatch name\",\"verifier_log\":\"\","
		     "\"loader_return\":0,\"upatch\":{\"path\":\"a.upatch\","
		     "\"name\":\"a\",\"payload_sha256\":\"\"},"
		     "\"kernel\":{\"release\":\"7.4.0\"},\"tpm\":null}");
	xfree(doc, cap);
}

/*
 * The verifier log quotes source lines and file names as the compiler
 * took them, and the release is the kernel's to choose.
 */
static void text_that_is_no_utf8_is_written(void)
{
	struct op_report r = {
		.op = "upatch_load",
		.phase = "payload_load",
		.err = EACCES,
		.category = "verifier_rejected",
		.path = "caf\xe9.upatch",
		.name = "\xff",
	};
	size_t cap;
	char *doc;

	report_set_log(&r, "; return na\xefve; @ caf\xe9.bpf.c:7\n");
	ASSERT_TRUE(r.verifier_log);
	ASSERT_EQ(report_encode(&r, "7.4.0-\xfe", &doc, &cap), 0);
	EXPECT_TRUE(str_contains(doc, "\"verifier_log\":\"; return na" FFFD
				 "ve; @ caf" FFFD ".bpf.c:7\\n\""));
	EXPECT_TRUE(str_contains(doc, "\"path\":\"caf" FFFD ".upatch\""));
	EXPECT_TRUE(str_contains(doc, "\"name\":\"" FFFD "\""));
	EXPECT_TRUE(str_contains(doc, "\"kernel\":{\"release\":\"7.4.0-" FFFD
				 "\"}"));
	xfree(doc, cap);
	report_free(&r);
}

static const struct unit_case cases[] = {
	UNIT_CASE(a_refusal_is_one_document),
	UNIT_CASE(text_that_is_no_utf8_is_written),
	{}
};

UNIT_SUITE(report, cases);
