// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdint.h>

#include <shirudo/overflow.h>

#include "unit.h"

struct flex {
	__u64	head;
	__u32	tail[];
};

static void check_overflow_judges_by_the_destination(void)
{
	__u64 u64;
	size_t sz;
	__u32 u32;
	__u8 u8;
	__s8 s8;

	EXPECT_FALSE(check_add_overflow(200, 55, &u8));
	EXPECT_EQ(u8, 255);
	EXPECT_TRUE(check_add_overflow(200, 56, &u8));
	EXPECT_EQ(u8, 0);
	EXPECT_FALSE(check_add_overflow((__u32)UINT32_MAX, 1, &u64));
	EXPECT_UEQ(u64, 1ULL << 32);
	EXPECT_TRUE(check_add_overflow((size_t)SIZE_MAX, 1, &sz));
	EXPECT_TRUE(check_sub_overflow(0u, 1u, &u32));
	EXPECT_FALSE(check_sub_overflow(0, 1, &s8));
	EXPECT_EQ(s8, -1);
	EXPECT_TRUE(check_sub_overflow(-100, 100, &s8));
	EXPECT_FALSE(check_mul_overflow(SIZE_MAX / 2, 2, &sz));
	EXPECT_UEQ(sz, SIZE_MAX - 1);
	EXPECT_TRUE(check_mul_overflow(SIZE_MAX / 2 + 1, 2, &sz));
	EXPECT_TRUE(check_mul_overflow(0x10000u, 0x10000u, &u32));
}

static void sizes_stick_at_size_max(void)
{
	EXPECT_UEQ(size_add(2, 3), 5);
	EXPECT_UEQ(size_add(SIZE_MAX, 1), SIZE_MAX);
	EXPECT_UEQ(size_mul(4, 5), 20);
	EXPECT_UEQ(size_mul(SIZE_MAX / 2 + 1, 2), SIZE_MAX);
	EXPECT_UEQ(size_sub(5, 3), 2);
	EXPECT_UEQ(size_sub(3, 5), SIZE_MAX);
	EXPECT_UEQ(size_sub(SIZE_MAX, 1), SIZE_MAX);
	EXPECT_UEQ(size_sub(10, SIZE_MAX), SIZE_MAX);
	EXPECT_UEQ(size_add(size_mul(SIZE_MAX, 2), 1), SIZE_MAX);
}

static void struct_size_counts_the_flexible_array(void)
{
	struct flex *p = NULL;

	EXPECT_UEQ(struct_size(p, tail, 0), sizeof(*p));
	EXPECT_UEQ(struct_size(p, tail, 3), sizeof(*p) + 3 * sizeof(__u32));
	EXPECT_UEQ(struct_size(p, tail, SIZE_MAX / 4), SIZE_MAX);
}

static void div_round_up_never_wraps(void)
{
	EXPECT_UEQ(DIV_ROUND_UP(0U, 8U), 0);
	EXPECT_UEQ(DIV_ROUND_UP(1U, 8U), 1);
	EXPECT_UEQ(DIV_ROUND_UP(8U, 8U), 1);
	EXPECT_UEQ(DIV_ROUND_UP(9U, 8U), 2);
	EXPECT_UEQ(DIV_ROUND_UP(UINT32_MAX, 8U), 0x20000000);
	EXPECT_UEQ(DIV_ROUND_UP(SIZE_MAX, (size_t)2), SIZE_MAX / 2 + 1);
}

static const struct unit_case cases[] = {
	UNIT_CASE(check_overflow_judges_by_the_destination),
	UNIT_CASE(sizes_stick_at_size_max),
	UNIT_CASE(struct_size_counts_the_flexible_array),
	UNIT_CASE(div_round_up_never_wraps),
	{}
};

UNIT_SUITE(overflow, cases);
