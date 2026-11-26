/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_KERNEL_RELEASE_H
#define SHIRUDO_KERNEL_RELEASE_H

#include <stdbool.h>

bool kernel_release_prefix_matches(const char *release,
				   const char *prefix);

#endif /* SHIRUDO_KERNEL_RELEASE_H */
