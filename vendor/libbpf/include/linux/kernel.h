/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The subset of the kernel's tools/include/linux/kernel.h libbpf uses.
 */

#ifndef SHIRUDO_VENDOR_LINUX_KERNEL_H
#define SHIRUDO_VENDOR_LINUX_KERNEL_H

#include <byteswap.h>
#include <endian.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/compiler.h>
#include <linux/types.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({				\
	const __typeof__(((type *)0)->member) *__mptr = (ptr);		\
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif
#ifndef roundup
#define roundup(x, y) ({				\
	__typeof__(y) __y = (y);			\
	(((x) + (__y - 1)) / __y) * __y; })
#endif

#ifndef min
#define min(x, y) ({				\
	__typeof__(x) _min1 = (x);		\
	__typeof__(y) _min2 = (y);		\
	(void)(&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#endif
#ifndef max
#define max(x, y) ({				\
	__typeof__(x) _max1 = (x);		\
	__typeof__(y) _max2 = (y);		\
	(void)(&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be16(x)		bswap_16(x)
#define cpu_to_be32(x)		bswap_32(x)
#define cpu_to_be64(x)		bswap_64(x)
#define be16_to_cpu(x)		bswap_16(x)
#define be32_to_cpu(x)		bswap_32(x)
#define be64_to_cpu(x)		bswap_64(x)
#define cpu_to_le16(x)		(x)
#define cpu_to_le32(x)		(x)
#define cpu_to_le64(x)		(x)
#define le16_to_cpu(x)		(x)
#define le32_to_cpu(x)		(x)
#define le64_to_cpu(x)		(x)
#else
#define cpu_to_be16(x)		(x)
#define cpu_to_be32(x)		(x)
#define cpu_to_be64(x)		(x)
#define be16_to_cpu(x)		(x)
#define be32_to_cpu(x)		(x)
#define be64_to_cpu(x)		(x)
#define cpu_to_le16(x)		bswap_16(x)
#define cpu_to_le32(x)		bswap_32(x)
#define cpu_to_le64(x)		bswap_64(x)
#define le16_to_cpu(x)		bswap_16(x)
#define le32_to_cpu(x)		bswap_32(x)
#define le64_to_cpu(x)		bswap_64(x)
#endif

#endif /* SHIRUDO_VENDOR_LINUX_KERNEL_H */
