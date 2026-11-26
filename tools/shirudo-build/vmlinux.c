// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * vmlinux.h locator.
 */

#include <stddef.h>
#include <unistd.h>

#include "vmlinux.h"

#ifndef VMLINUX_PATH
#define VMLINUX_PATH "/usr/local/share/shirudo/vmlinux.h"
#endif

const char *build_locate_vmlinux(const char *override)
{
	if (override)
		return access(override, R_OK) == 0 ? override : NULL;
	if (access("./vmlinux.h", R_OK) == 0)
		return "./vmlinux.h";
	if (access("./vendor/linux/vmlinux.h", R_OK) == 0)
		return "./vendor/linux/vmlinux.h";
	if (access(VMLINUX_PATH, R_OK) == 0)
		return VMLINUX_PATH;
	return NULL;
}
