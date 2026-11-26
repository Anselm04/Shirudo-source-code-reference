/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The kernel's fixed-width and byte-order types, for userspace.
 */

#ifndef SHIRUDO_TYPES_H
#define SHIRUDO_TYPES_H

/*
 * The UAPI header's own types, the ones every kernel and libbpf header
 * uses: __u8 to __s64 as on x86-64, arm64 and riscv64, and __le16 to
 * __be64, which sparse checks as restricted types.
 */
#include <linux/types.h>

#endif /* SHIRUDO_TYPES_H */
