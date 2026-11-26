// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>

#include "kernel_prereq.h"
#include "unit.h"

/* A BTF with a function of each name and nothing else of note. */
static struct btf *btf_with(const char *const *names, size_t n)
{
	int ret_type, proto;
	struct btf *btf;
	size_t i;

	btf = btf__new_empty();
	if (libbpf_get_error(btf))
		return NULL;
	ret_type = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	proto = btf__add_func_proto(btf, ret_type);
	if (ret_type < 0 || proto < 0)
		goto err;
	for (i = 0; i < n; i++)
		if (btf__add_func(btf, names[i], BTF_FUNC_GLOBAL, proto) < 0)
			goto err;
	return btf;
err:
	btf__free(btf);
	return NULL;
}

static void options_of(const char *const *names, size_t n,
		       struct kernel_options *opts)
{
	struct btf *btf = btf_with(names, n);

	ASSERT_TRUE(btf);
	memset(opts, 0xff, sizeof(*opts));
	kernel_prereq_options(btf, opts);
	btf__free(btf);
}

static void options_of_a_kernel_with_all(void)
{
	static const char *const names[] = {
		"__module_address", "mod_verify_sig",
	};
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_TRUE(opts.module_sig);
}

static void options_of_a_kernel_with_none(void)
{
	static const char *const names[] = { "vfs_read", "module" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_FALSE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
}

static void modules_without_signatures(void)
{
	static const char *const names[] = { "__module_address" };
	struct kernel_options opts;

	options_of(names, ARRAY_SIZE(names), &opts);
	EXPECT_TRUE(opts.modules);
	EXPECT_FALSE(opts.module_sig);
}

static const struct unit_case cases[] = {
	UNIT_CASE(options_of_a_kernel_with_all),
	UNIT_CASE(options_of_a_kernel_with_none),
	UNIT_CASE(modules_without_signatures),
	{}
};

UNIT_SUITE(kernel_prereq, cases);
