// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stddef.h>

#include "log.h"
#include "unit.h"

static void stream_names_its_file(void)
{
	EXPECT_TRUE(log_stream_is("8:1234", 8, 1234));
	EXPECT_TRUE(log_stream_is("0:0", 0, 0));
	EXPECT_TRUE(log_stream_is("18446744073709551615:1",
				  18446744073709551615ULL, 1));
}

static void stream_of_another_file(void)
{
	EXPECT_FALSE(log_stream_is("8:1234", 8, 1235));
	EXPECT_FALSE(log_stream_is("8:1234", 9, 1234));
	EXPECT_FALSE(log_stream_is("1234:8", 8, 1234));
}

static void stream_that_is_no_pair_of_numbers(void)
{
	EXPECT_FALSE(log_stream_is(NULL, 0, 0));
	EXPECT_FALSE(log_stream_is("", 0, 0));
	EXPECT_FALSE(log_stream_is(":", 0, 0));
	EXPECT_FALSE(log_stream_is("8", 8, 0));
	EXPECT_FALSE(log_stream_is("8:", 8, 0));
	EXPECT_FALSE(log_stream_is(":1234", 0, 1234));
	EXPECT_FALSE(log_stream_is("8:1234 ", 8, 1234));
	EXPECT_FALSE(log_stream_is(" 8:1234", 8, 1234));
	EXPECT_FALSE(log_stream_is("8:1234:5", 8, 1234));
	EXPECT_FALSE(log_stream_is("0x8:1234", 8, 1234));
	EXPECT_FALSE(log_stream_is("-8:1234", 8, 1234));
	EXPECT_FALSE(log_stream_is("18446744073709551616:1", 0, 1));
}

static const struct unit_case cases[] = {
	UNIT_CASE(stream_names_its_file),
	UNIT_CASE(stream_of_another_file),
	UNIT_CASE(stream_that_is_no_pair_of_numbers),
	{}
};

UNIT_SUITE(log, cases);
