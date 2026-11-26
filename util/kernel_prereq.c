// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes,
 * for the pre-flight checks of init.
 */

#include <stdbool.h>

#include <linux/btf.h>

#include <bpf/btf.h>

#include "kernel_prereq.h"

static bool has_func(const struct btf *btf, const char *name)
{
	return btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) > 0;
}

/*
 * Each name is a function only its option builds. Without the option
 * its stub, where it has one, is a static inline, which leaves no BTF
 * function.
 */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out)
{
	out->modules = has_func(btf, "__module_address");
	out->module_sig = has_func(btf, "mod_verify_sig");
}
