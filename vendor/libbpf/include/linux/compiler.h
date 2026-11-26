/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Compiler helpers libbpf expects from the kernel's tools/include.
 */

#ifndef SHIRUDO_VENDOR_LINUX_COMPILER_H
#define SHIRUDO_VENDOR_LINUX_COMPILER_H

#ifndef __always_inline
#define __always_inline		inline __attribute__((always_inline))
#endif
#ifndef noinline
#define noinline		__attribute__((noinline))
#endif
#ifndef __maybe_unused
#define __maybe_unused		__attribute__((unused))
#endif
#ifndef __packed
#define __packed		__attribute__((packed))
#endif
#ifndef likely
#define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)		__builtin_expect(!!(x), 0)
#endif
#ifndef barrier
#define barrier()		__asm__ __volatile__("" : : : "memory")
#endif
#ifndef unreachable
#define unreachable()		__builtin_unreachable()
#endif
#ifndef READ_ONCE
#define READ_ONCE(x)		(*(volatile __typeof__(x) *)&(x))
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)	(*(volatile __typeof__(x) *)&(x) = (v))
#endif

#endif /* SHIRUDO_VENDOR_LINUX_COMPILER_H */
