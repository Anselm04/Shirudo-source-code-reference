/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Acquire/release accessors for libbpf's ring buffer consumers.
 */

#ifndef SHIRUDO_VENDOR_ASM_BARRIER_H
#define SHIRUDO_VENDOR_ASM_BARRIER_H

#define smp_store_release(p, v)	__atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define smp_load_acquire(p)	__atomic_load_n((p), __ATOMIC_ACQUIRE)

#endif /* SHIRUDO_VENDOR_ASM_BARRIER_H */
