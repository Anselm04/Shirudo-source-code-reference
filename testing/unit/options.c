// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>

#include "help.h"
#include "options.h"
#include "unit.h"

enum {
	T_CERT,
	T_FORCE,
	T_OUTPUT,
	T_JSON,
	T_ADD,
	T_TAG,
	T_COUNT,
};

static const struct opt_spec specs[] = {
	[T_CERT]   = { "--cert", 0, 0, "<path>", "a certificate" },
	[T_FORCE]  = { "--force", 'f', 0, NULL, "overwrite" },
	[T_OUTPUT] = { "--output", 'o', 0, "<path>", "where to write" },
	[T_JSON]   = { "--json", 0, OPT_OPTIONAL, "<path>", "JSON, to a file" },
	[T_ADD]    = { "--add", 0, OPT_REPEAT, "<name>", "one more name" },
	[T_TAG]    = { "--tag", 0, OPT_EMPTY, "<tag>", "a tag, may be empty" },
	[T_COUNT]  = { "--count", 0, 0, "<n>", "how many" },
};

static void parse(struct opt_parser *p, const char *const *argv, int argc)
{
	OPT_INIT(p, "test", specs, NULL, argc, argv, 0);
}

static void both_value_forms_give_the_same(void)
{
	static const char *const argv[] = { "--cert", "a.der", "--output=b" };
	struct opt_parser p;

	parse(&p, argv, 3);
	ASSERT_EQ(opt_next(&p), T_CERT);
	EXPECT_STREQ(p.value, "a.der");
	ASSERT_EQ(opt_next(&p), T_OUTPUT);
	EXPECT_STREQ(p.value, "b");
	EXPECT_EQ(opt_next(&p), OPT_END);
	EXPECT_TRUE(opt_given(&p, T_CERT));
	EXPECT_FALSE(opt_given(&p, T_FORCE));
}

static void a_value_must_be_there_and_not_empty(void)
{
	static const char *const last[] = { "--cert" };
	static const char *const empty[] = { "--cert=" };
	static const char *const tag[] = { "--tag=" };
	struct opt_parser p;

	parse(&p, last, 1);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	parse(&p, empty, 1);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	parse(&p, tag, 1);
	ASSERT_EQ(opt_next(&p), T_TAG);
	EXPECT_STREQ(p.value, "");
}

static void a_flag_takes_no_value(void)
{
	static const char *const ok[] = { "-f" };
	static const char *const bad[] = { "--force=yes" };
	struct opt_parser p;

	parse(&p, ok, 1);
	EXPECT_EQ(opt_next(&p), T_FORCE);
	EXPECT_TRUE(!p.value);
	parse(&p, bad, 1);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
}

static void an_option_comes_once_unless_it_repeats(void)
{
	static const char *const twice[] = { "--cert", "a", "--cert=b" };
	static const char *const alias[] = { "-f", "--force" };
	static const char *const repeat[] = { "--add", "x", "--add=y" };
	struct opt_parser p;

	parse(&p, twice, 3);
	ASSERT_EQ(opt_next(&p), T_CERT);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	parse(&p, alias, 2);
	ASSERT_EQ(opt_next(&p), T_FORCE);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	parse(&p, repeat, 3);
	ASSERT_EQ(opt_next(&p), T_ADD);
	EXPECT_STREQ(p.value, "x");
	ASSERT_EQ(opt_next(&p), T_ADD);
	EXPECT_STREQ(p.value, "y");
}

static void unknown_and_glued_options_are_refused(void)
{
	static const char *const bad[][1] = {
		{ "--crt" }, { "--cert-file=x" }, { "-x" }, { "-oout" },
		{ "-fo" }, { "--c" },
	};
	struct opt_parser p;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		parse(&p, bad[i], 1);
		EXPECT_EQ(opt_next(&p), OPT_USAGE);
	}
}

static void arguments_interleave_and_double_dash_ends_options(void)
{
	static const char *const argv[] = { "pkg", "-o", "x", "-", "--", "--cert", "-f" };
	struct opt_parser p;

	parse(&p, argv, 7);
	ASSERT_EQ(opt_next(&p), OPT_ARG);
	EXPECT_STREQ(p.value, "pkg");
	ASSERT_EQ(opt_next(&p), T_OUTPUT);
	EXPECT_STREQ(p.value, "x");
	ASSERT_EQ(opt_next(&p), OPT_ARG);
	EXPECT_STREQ(p.value, "-");
	ASSERT_EQ(opt_next(&p), OPT_ARG);
	EXPECT_STREQ(p.value, "--cert");
	ASSERT_EQ(opt_next(&p), OPT_ARG);
	EXPECT_STREQ(p.value, "-f");
	EXPECT_EQ(opt_next(&p), OPT_END);
}

static void an_optional_value_comes_after_equals_alone(void)
{
	static const char *const argv[] = { "--json", "file", "--output", "o" };
	static const char *const eq[] = { "--json=log.ndjson" };
	struct opt_parser p;

	parse(&p, argv, 4);
	ASSERT_EQ(opt_next(&p), T_JSON);
	EXPECT_TRUE(!p.value);
	ASSERT_EQ(opt_next(&p), OPT_ARG);
	EXPECT_STREQ(p.value, "file");
	parse(&p, eq, 1);
	ASSERT_EQ(opt_next(&p), T_JSON);
	EXPECT_STREQ(p.value, "log.ndjson");
}

static void help_and_the_option_list_end_parsing(void)
{
	static const char *const help[] = { "--cert", "a", "-h", "--bogus" };
	static const char *const list[] = { "--list-opts" };
	static const char *const cmds[] = { "--list-cmds" };
	struct opt_parser p;
	FILE *saved = stdout;

	parse(&p, help, 4);
	ASSERT_EQ(opt_next(&p), T_CERT);
	EXPECT_EQ(opt_next(&p), OPT_DONE);
	stdout = fopen("/dev/null", "w");
	ASSERT_TRUE(stdout);
	parse(&p, list, 1);
	EXPECT_EQ(opt_next(&p), OPT_DONE);
	parse(&p, cmds, 1);
	EXPECT_EQ(opt_next(&p), OPT_DONE);
	EXPECT_EQ(fclose(stdout), 0);
	stdout = saved;
}

static void a_number_is_bounded(void)
{
	static const char *const ok[] = { "--count", "512" };
	static const char *const low[] = { "--count=0" };
	static const char *const high[] = { "--count=513" };
	static const char *const word[] = { "--count=ten" };
	static const char *const *const bad[] = { low, high, word };
	struct opt_parser p;
	__u64 n = 0;
	size_t i;

	parse(&p, ok, 2);
	ASSERT_EQ(opt_next(&p), T_COUNT);
	ASSERT_EQ(opt_u64(&p, 1, 512, &n), 0);
	EXPECT_UEQ(n, 512);
	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		parse(&p, bad[i], 1);
		ASSERT_EQ(opt_next(&p), T_COUNT);
		EXPECT_EQ(opt_u64(&p, 1, 512, &n), OPT_USAGE);
	}
	parse(&p, ok, 0);
	EXPECT_EQ(opt_next(&p), OPT_END);
	EXPECT_EQ(opt_u64(&p, 1, 512, &n), OPT_USAGE);
}

static void a_choice_names_its_value(void)
{
	static const struct opt_name ops[] = {
		{ "add", 0 },
		{ "delete", 1 },
	};
	static const char *const del[] = { "--tag=delete" };
	static const char *const bad[] = { "--tag=remove" };
	struct opt_parser p;
	int op = -1;

	parse(&p, del, 1);
	ASSERT_EQ(opt_next(&p), T_TAG);
	ASSERT_EQ(OPT_CHOICE(&p, ops, &op), 0);
	EXPECT_EQ(op, 1);
	op = -1;
	parse(&p, bad, 1);
	ASSERT_EQ(opt_next(&p), T_TAG);
	EXPECT_EQ(OPT_CHOICE(&p, ops, &op), OPT_USAGE);
	EXPECT_EQ(op, -1);
}

static void a_malformed_table_is_refused_before_any_argument(void)
{
	static const struct opt_spec hole[] = {
		[1] = { "--a", 0, 0, NULL, "a" },
	};
	static const struct opt_spec twice[] = {
		{ "--a", 0, 0, NULL, "a" },
		{ "--a", 0, 0, "<x>", "a again" },
	};
	static const struct opt_spec flag_with_flags[] = {
		{ "--a", 0, OPT_EMPTY, NULL, "a" },
	};
	static const struct opt_spec no_dashes[] = {
		{ "a", 0, 0, NULL, "a" },
	};
	static const char *const argv[] = { "arg" };
	struct opt_parser p;

	OPT_INIT(&p, "test", hole, NULL, 1, argv, 0);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	OPT_INIT(&p, "test", twice, NULL, 1, argv, 0);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	OPT_INIT(&p, "test", flag_with_flags, NULL, 1, argv, 0);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
	OPT_INIT(&p, "test", no_dashes, NULL, 1, argv, 0);
	EXPECT_EQ(opt_next(&p), OPT_USAGE);
}

static const struct unit_case cases[] = {
	UNIT_CASE(both_value_forms_give_the_same),
	UNIT_CASE(a_value_must_be_there_and_not_empty),
	UNIT_CASE(a_flag_takes_no_value),
	UNIT_CASE(an_option_comes_once_unless_it_repeats),
	UNIT_CASE(unknown_and_glued_options_are_refused),
	UNIT_CASE(arguments_interleave_and_double_dash_ends_options),
	UNIT_CASE(an_optional_value_comes_after_equals_alone),
	UNIT_CASE(help_and_the_option_list_end_parsing),
	UNIT_CASE(a_number_is_bounded),
	UNIT_CASE(a_choice_names_its_value),
	UNIT_CASE(a_malformed_table_is_refused_before_any_argument),
	{}
};

UNIT_SUITE(options, cases);
