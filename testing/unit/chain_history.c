// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "chain.h"
#include "hex.h"
#include "unit.h"

/*
 * The operation digests of a three-operation tree, and the history root
 * after none, one, two and all of them as Python's hashlib gives it:
 *
 *   root = bytes(32)
 *   for d in digests:
 *       root = sha256(b"shirudo-tree-history\0" + root + d).digest()
 */
static const char *const tree_operations[] = {
	"13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43",
	"5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b",
	"bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc",
};

static const char *const history_roots[] = {
	"0000000000000000000000000000000000000000000000000000000000000000",
	"470779d64e1302c4826a4be3222020050e70784ae6016040eabde9d0d8770d80",
	"889efeb27650c0111168d523c935f051addbcc049d079e440e518dd3939722f0",
	"bdc9ee89e753beca03d6e9ae89344269cb3a2e8ba3662122f55b1e3f7ff34011",
};

static void history_root_after(size_t n, char hex[2 * 32 + 1])
{
	__u8 root[32] = {}, digest[32];
	size_t i;

	for (i = 0; i < n; i++) {
		ASSERT_EQ(hex_decode(tree_operations[i], digest, 32), 0);
		ASSERT_EQ(chain_history_step(root, digest, root), 0);
	}
	hex_encode(root, sizeof(root), hex);
}

static void history_root_matches_the_reference(void)
{
	char hex[2 * 32 + 1];

	history_root_after(0, hex);
	EXPECT_STREQ(hex, history_roots[0]);
	history_root_after(1, hex);
	EXPECT_STREQ(hex, history_roots[1]);
	history_root_after(3, hex);
	EXPECT_STREQ(hex, history_roots[3]);
}

static void history_step_writes_beside_its_input(void)
{
	__u8 prev[32] = {}, zero[32] = {}, digest[32], out[32];
	char hex[2 * 32 + 1];

	ASSERT_EQ(hex_decode(tree_operations[0], digest, 32), 0);
	ASSERT_EQ(chain_history_step(prev, digest, out), 0);
	hex_encode(out, sizeof(out), hex);
	EXPECT_STREQ(hex, history_roots[1]);
	EXPECT_MEMEQ(prev, zero, sizeof(prev));
}

static void history_root_differs_from_the_projection_root(void)
{
	static const char *const projection_roots[] = {
		"04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136",
		"a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93",
		"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1",
	};
	__u8 history[32] = {}, projection[32] = {}, digest[32];
	char hex[2 * 32 + 1];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(tree_operations); i++) {
		ASSERT_EQ(hex_decode(tree_operations[i], digest, 32), 0);
		ASSERT_EQ(chain_history_step(history, digest, history), 0);
		ASSERT_EQ(sha256_2(projection, 32, digest, 32, projection), 0);
		hex_encode(projection, sizeof(projection), hex);
		EXPECT_STREQ(hex, projection_roots[i]);
		hex_encode(history, sizeof(history), hex);
		EXPECT_STREQ(hex, history_roots[i + 1]);
		EXPECT_TRUE(memcmp(history, projection, sizeof(history)) != 0);
	}
}

static const struct unit_case cases[] = {
	UNIT_CASE(history_root_matches_the_reference),
	UNIT_CASE(history_step_writes_beside_its_input),
	UNIT_CASE(history_root_differs_from_the_projection_root),
	{}
};

UNIT_SUITE(chain_history, cases);
