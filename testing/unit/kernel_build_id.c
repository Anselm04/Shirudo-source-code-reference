// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>

#include "kernel_build_id.h"
#include "unit.h"

/* One GNU build-id note with a four-byte descriptor: 01 23 45 67. */
static const __u8 notes[] = {
	4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0,
	'G', 'N', 'U', 0, 0x01, 0x23, 0x45, 0x67,
};

static void gnu_note_gives_the_build_id(void)
{
	char id[KERNEL_BUILD_ID_STRING_MAX];

	ASSERT_EQ(kernel_build_id_from_notes(notes, sizeof(notes), id), 0);
	EXPECT_STREQ(id, "01234567");
}

static void empty_notes_have_no_build_id(void)
{
	char id[KERNEL_BUILD_ID_STRING_MAX];

	EXPECT_EQ(kernel_build_id_from_notes(notes, 0, id), -ENOENT);
}

static void oversized_name_is_malformed(void)
{
	char id[KERNEL_BUILD_ID_STRING_MAX];
	__u8 bad[sizeof(notes)];
	__u32 namesz = ~0U;

	memcpy(bad, notes, sizeof(notes));
	memcpy(bad, &namesz, sizeof(namesz));
	EXPECT_EQ(kernel_build_id_from_notes(bad, sizeof(bad), id), -EINVAL);
}

/* A vendor's type-3 note first, then the GNU one. */
static void only_the_gnu_name_names_the_build_id(void)
{
	static const __u8 vendor[] = {
		4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0,
		'G', 'N', 'U', 'X', 0x89, 0xab, 0xcd, 0xef,
		4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0,
		'G', 'N', 'U', 0, 0x01, 0x23, 0x45, 0x67,
	};
	char id[KERNEL_BUILD_ID_STRING_MAX];

	ASSERT_EQ(kernel_build_id_from_notes(vendor, sizeof(vendor), id), 0);
	EXPECT_STREQ(id, "01234567");
	EXPECT_EQ(kernel_build_id_from_notes(vendor, 20, id), -ENOENT);
}

static const struct unit_case cases[] = {
	UNIT_CASE(gnu_note_gives_the_build_id),
	UNIT_CASE(empty_notes_have_no_build_id),
	UNIT_CASE(oversized_name_is_malformed),
	UNIT_CASE(only_the_gnu_name_names_the_build_id),
	{}
};

UNIT_SUITE(kernel_build_id, cases);
