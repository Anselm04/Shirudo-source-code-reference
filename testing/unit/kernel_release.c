// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "kernel_release.h"
#include "unit.h"

static void prefix_matches_at_a_boundary(void)
{
	EXPECT_TRUE(kernel_release_prefix_matches("6.1.0", "6.1"));
	EXPECT_TRUE(kernel_release_prefix_matches("6.1-custom", "6.1"));
	EXPECT_TRUE(kernel_release_prefix_matches("6.1", "6.1"));
	EXPECT_FALSE(kernel_release_prefix_matches("6.10.0", "6.1"));
}

static void empty_prefix_matches_any_release(void)
{
	EXPECT_TRUE(kernel_release_prefix_matches("6.1.0", ""));
	EXPECT_FALSE(kernel_release_prefix_matches("", "6.1"));
}

static void missing_release_or_prefix_never_matches(void)
{
	EXPECT_FALSE(kernel_release_prefix_matches(NULL, "6.1"));
	EXPECT_FALSE(kernel_release_prefix_matches("6.1.0", NULL));
}

static const struct unit_case cases[] = {
	UNIT_CASE(prefix_matches_at_a_boundary),
	UNIT_CASE(empty_prefix_matches_any_release),
	UNIT_CASE(missing_release_or_prefix_never_matches),
	{}
};

UNIT_SUITE(kernel_release, cases);
