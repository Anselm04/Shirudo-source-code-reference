// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/string.h>

#include "bpm_state.h"
#include "paths.h"
#include "unit.h"

static void entry(struct bpm_state_entry *e, const char *name,
		  const char *version)
{
	ASSERT_TRUE(strscpy(e->name, name, sizeof(e->name)) > 0);
	ASSERT_TRUE(strscpy(e->version, version, sizeof(e->version)) > 0);
	strscpy_literal(e->source, "main");
	ASSERT_TRUE(strsprintf(e->path, sizeof(e->path), "%s/%s/%s",
			       BPM_PACKAGES_DIR, name, version) > 0);
}

static struct bpm_state_entry out[BPM_MAX_STATE];

static void state_reads_back_what_it_writes(void)
{
	struct bpm_state_entry in[2] = {};
	char buf[4096];
	size_t len;
	int n;

	entry(&in[0], "kernel-obs", "1.0.0");
	entry(&in[1], "fix", "2.1.0-rc.1");
	ASSERT_EQ(bpm_state_emit(in, 2, buf, sizeof(buf), &len), 0);
	ASSERT_EQ(bpm_state_parse(buf, len, out, &n), 0);
	EXPECT_EQ(n, 2);
	EXPECT_MEMEQ(out, in, sizeof(in));
	EXPECT_EQ(bpm_state_emit(in, 2, buf, 16, &len), -E2BIG);
}

static void state_refuses_an_entry_out_of_place(void)
{
	struct bpm_state_entry in = {};
	char buf[4096];
	size_t len;
	int n;

	entry(&in, "fix", "1.0.0");
	in.path[strlen(in.path) - 1] = '1';
	ASSERT_EQ(bpm_state_emit(&in, 1, buf, sizeof(buf), &len), 0);
	EXPECT_EQ(bpm_state_parse(buf, len, out, &n), -EINVAL);
	entry(&in, "../fix", "1.0.0");
	ASSERT_EQ(bpm_state_emit(&in, 1, buf, sizeof(buf), &len), 0);
	EXPECT_EQ(bpm_state_parse(buf, len, out, &n), -EINVAL);
	EXPECT_EQ(bpm_state_parse("{\"schema\":1}", 12, out, &n), -EINVAL);
	in.name[0] = '\0';
	ASSERT_EQ(bpm_state_emit(&in, 1, buf, sizeof(buf), &len), 0);
	EXPECT_EQ(bpm_state_parse(buf, len, out, &n), -EINVAL);
}

static const struct unit_case cases[] = {
	UNIT_CASE(state_reads_back_what_it_writes),
	UNIT_CASE(state_refuses_an_entry_out_of_place),
	{}
};

UNIT_SUITE(bpm_state, cases);
