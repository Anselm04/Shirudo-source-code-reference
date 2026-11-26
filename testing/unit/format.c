// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "format.h"
#include "unit.h"

static void shown(const char *s, char *out, size_t cap)
{
	FILE *f = fmemopen(out, cap, "w");

	ASSERT_TRUE(f);
	fputs_sanitized(s, f);
	ASSERT_EQ(fclose(f), 0);
}

static void fputs_sanitized_keeps_a_terminal_safe(void)
{
	char out[1024];

	shown("CN=shirudo, O=Example", out, sizeof(out));
	EXPECT_STREQ(out, "CN=shirudo, O=Example");
	shown("CN=\x1b]0;owned\x07\n", out, sizeof(out));
	EXPECT_STREQ(out, "CN=?]0;owned??");
	shown("CN=caf\xc3\xa9 \xff", out, sizeof(out));
	EXPECT_STREQ(out, "CN=caf\xc3\xa9 ?");
}

static void fputs_sanitized_cuts_after_511_bytes(void)
{
	char in[600], out[1024];

	memset(in, 'a', sizeof(in) - 1);
	in[sizeof(in) - 1] = '\0';
	shown(in, out, sizeof(out));
	EXPECT_EQ(strlen(out), 511);
}

static void human_size_picks_the_unit(void)
{
	char out[16];

	EXPECT_EQ(human_size(512, out, sizeof(out)), 0);
	EXPECT_STREQ(out, "512B");
	EXPECT_EQ(human_size(1536, out, sizeof(out)), 0);
	EXPECT_STREQ(out, "1.50K");
	EXPECT_EQ(human_size(1536, out, 4), -E2BIG);
}

static const struct unit_case cases[] = {
	UNIT_CASE(fputs_sanitized_keeps_a_terminal_safe),
	UNIT_CASE(fputs_sanitized_cuts_after_511_bytes),
	UNIT_CASE(human_size_picks_the_unit),
	{}
};

UNIT_SUITE(format, cases);
