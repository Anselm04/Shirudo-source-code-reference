/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes:
 * its BTF, not /proc/config.gz, which a target need not have.
 */

#ifndef SHIRUDO_KERNEL_PREREQ_H
#define SHIRUDO_KERNEL_PREREQ_H

#include <stdbool.h>

struct btf;

struct kernel_options {
	bool	modules;	/* CONFIG_MODULES */
	bool	module_sig;	/* CONFIG_MODULE_SIG */
};

/* The options btf shows, the BTF of vmlinux. */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out);

#endif /* SHIRUDO_KERNEL_PREREQ_H */
