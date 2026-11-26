// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kconfig.h"
#include "unit.h"

static char line[256];
static const char *key, *value;

static bool sets(const char *text)
{
	key = "";
	value = "";
	ASSERT_TRUE(strscpy(line, text, sizeof(line)) >= 0);
	return kconfig_line(line, &key, &value);
}

static void an_option_has_its_value(void)
{
	ASSERT_TRUE(sets("CONFIG_BPF_LSM=y"));
	EXPECT_STREQ(key, "CONFIG_BPF_LSM");
	EXPECT_STREQ(value, "y");
	ASSERT_TRUE(sets("CONFIG_HZ=250"));
	EXPECT_STREQ(value, "250");
	ASSERT_TRUE(sets("CONFIG_INITRAMFS_SOURCE="));
	EXPECT_STREQ(value, "");
}

static void a_string_comes_without_its_quotes(void)
{
	ASSERT_TRUE(sets("CONFIG_LSM=\"lockdown,bpf\""));
	EXPECT_STREQ(value, "lockdown,bpf");
	ASSERT_TRUE(sets("CONFIG_CMDLINE=\"console=ttyS0 quiet\""));
	EXPECT_STREQ(key, "CONFIG_CMDLINE");
	EXPECT_STREQ(value, "console=ttyS0 quiet");
	ASSERT_TRUE(sets("CONFIG_LOCALVERSION=\"\""));
	EXPECT_STREQ(value, "");
	ASSERT_TRUE(sets("CONFIG_LOCALVERSION=\""));
	EXPECT_STREQ(value, "\"");
}

static void an_option_not_set_is_n(void)
{
	ASSERT_TRUE(sets("# CONFIG_MODULES is not set"));
	EXPECT_STREQ(key, "CONFIG_MODULES");
	EXPECT_STREQ(value, "n");
}

static void white_space_around_is_no_part(void)
{
	ASSERT_TRUE(sets(" \tCONFIG_A = y \r"));
	EXPECT_STREQ(key, "CONFIG_A");
	EXPECT_STREQ(value, "y");
	ASSERT_TRUE(sets("\t# CONFIG_A is not set \r"));
	EXPECT_STREQ(key, "CONFIG_A");
	EXPECT_STREQ(value, "n");
}

static void any_other_line_sets_nothing(void)
{
	static const char * const lines[] = {
		"", " \t\r", "#", "# Automatically generated file; DO NOT EDIT.",
		"#CONFIG_A=y", "# CONFIG_A=y", "# CONFIG_A is not set at all",
		"# CONFIG_ is not set", "CONFIG_A", "CONFIG_=y", "A=y", "=y",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lines); i++)
		EXPECT_FALSE(sets(lines[i]));
}

static const struct unit_case cases[] = {
	UNIT_CASE(an_option_has_its_value),
	UNIT_CASE(a_string_comes_without_its_quotes),
	UNIT_CASE(an_option_not_set_is_n),
	UNIT_CASE(white_space_around_is_no_part),
	UNIT_CASE(any_other_line_sets_nothing),
	{}
};

UNIT_SUITE(kconfig, cases);
