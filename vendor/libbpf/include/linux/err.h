/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Kernel-style error pointers, as libbpf expects from tools/include.
 */

#ifndef SHIRUDO_VENDOR_LINUX_ERR_H
#define SHIRUDO_VENDOR_LINUX_ERR_H

#include <stdbool.h>

#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) \
	((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#endif /* SHIRUDO_VENDOR_LINUX_ERR_H */
