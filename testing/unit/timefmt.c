// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>

#include "timefmt.h"
#include "unit.h"

#define EPOCH	"1970-01-01T00:00:00Z"

static void unterminated(char *out, size_t cap)
{
	memset(out, 'X', cap - 1);
	out[cap - 1] = '\0';
}

static void iso8601_is_utc_to_the_second(void)
{
	char out[32];

	ASSERT_EQ(iso8601(0, out, sizeof(EPOCH)), 0);
	EXPECT_STREQ(out, EPOCH);
	ASSERT_EQ(iso8601(1700000000, out, sizeof(out)), 0);
	EXPECT_STREQ(out, "2023-11-14T22:13:20Z");
}

/*
 * The eventlog, status and upatch get show what iso8601() left without
 * looking at its result.
 */
static void iso8601_leaves_an_empty_string_when_it_fails(void)
{
	char out[32];

	unterminated(out, sizeof(out));
	EXPECT_EQ(iso8601(0, out, sizeof(EPOCH) - 1), -EINVAL);
	EXPECT_STREQ(out, "");
	unterminated(out, sizeof(out));
	EXPECT_EQ(iso8601((time_t)1 << 62, out, sizeof(out)), -EINVAL);
	EXPECT_STREQ(out, "");
}

static void format_duration_shows_the_largest_whole_unit(void)
{
	static const struct {
		__s64 seconds;
		const char *text;
	} durations[] = {
		{ 0, "0s" }, { 59, "59s" }, { 60, "1m" }, { 3599, "59m" },
		{ 3600, "1h" }, { 86399, "23h" }, { 86400, "1d" },
		{ 86400 * 400, "400d" }, { -1, "?" },
	};
	char out[16];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(durations); i++) {
		ASSERT_EQ(format_duration((long)durations[i].seconds, out,
					  sizeof(out)), 0);
		EXPECT_STREQ(out, durations[i].text);
	}
}

static void format_duration_leaves_an_empty_string_when_it_does_not_fit(void)
{
	char out[8];

	unterminated(out, sizeof(out));
	EXPECT_EQ(format_duration(3599, out, sizeof("59m") - 1), -E2BIG);
	EXPECT_STREQ(out, "");
	unterminated(out, sizeof(out));
	EXPECT_EQ(format_duration(-1, out, sizeof("?") - 1), -E2BIG);
	EXPECT_STREQ(out, "");
}

static const struct unit_case cases[] = {
	UNIT_CASE(iso8601_is_utc_to_the_second),
	UNIT_CASE(iso8601_leaves_an_empty_string_when_it_fails),
	UNIT_CASE(format_duration_shows_the_largest_whole_unit),
	UNIT_CASE(format_duration_leaves_an_empty_string_when_it_does_not_fit),
	{}
};

UNIT_SUITE(timefmt, cases);
