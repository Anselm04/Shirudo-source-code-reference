/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * ARRAY_SIZE(), offsetofend(), min() and max(), ptr_to_u64() and
 * shirudo_trunc() for userspace, with the kernel's types from
 * <shirudo/types.h>.
 */

#ifndef SHIRUDO_MISC_H
#define SHIRUDO_MISC_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <shirudo/compiler.h>
#include <shirudo/types.h>

/* 0, or no build when a is a pointer rather than an array. */
#define __must_be_array(a)						\
	BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a),	\
						       typeof(&(a)[0])))
#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]) + __must_be_array(a))

/* The text of x once its macros are expanded, as a string literal. */
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)

/*
 * The size of a member, and the offset just past it, without an object;
 * the member may be a path such as a.b, as offsetof() takes it.
 */
#define sizeof_field(type, ...)	sizeof(((type *)0)->__VA_ARGS__)
#define offsetofend(type, ...)						\
	(offsetof(type, __VA_ARGS__) + sizeof_field(type, __VA_ARGS__))

/*
 * Each argument is evaluated once, and two that compare differently as
 * signed and as unsigned refuse to compile rather than compare after a
 * silent conversion: both unsigned or both signed, of any width, or an
 * unsigned narrower than int, which C promotes to int. A constant
 * compared with an unsigned value takes a U suffix. The two compare in
 * the type C converts them to, which then holds both values. min_t()
 * and max_t() convert both to the type they name, which can cut a value
 * short, so they are for only what min() and max() refuse. The
 * temporaries take a __COUNTER__ suffix so that a nested call shadows
 * nothing.
 */
/* 1 when x compares as unsigned, 2 as signed, 3 either way. */
#define __sign_use(x)							\
	((typeof(x))(-1) < 1 ? 2 : sizeof(x) < sizeof(int) ? 3 : 1)
#define __minmax_op_min		<
#define __minmax_op_max		>
#define __minmax_n(op, x, y, n) ({					\
	__auto_type __x##n = (x);					\
	__auto_type __y##n = (y);					\
	typeof(__x##n + __y##n) __a##n = __x##n;			\
	typeof(__x##n + __y##n) __b##n = __y##n;			\
	BUILD_BUG_ON_MSG(!(__sign_use(__x##n) & __sign_use(__y##n)),	\
			 #op "(" #x ", " #y ") mixes signed and unsigned"); \
	__a##n __minmax_op_##op __b##n ? __a##n : __b##n; })
#define __minmax(op, x, y, n)	__minmax_n(op, x, y, n)
#define min(x, y)		__minmax(min, x, y, __COUNTER__)
#define max(x, y)		__minmax(max, x, y, __COUNTER__)
#define min_t(type, x, y)	min((type)(x), (type)(y))
#define max_t(type, x, y)	max((type)(x), (type)(y))

/* A pointer as the __u64 the bpf() ABI carries it in. */
static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

/*
 * trunc() without libm, which clang calls for it and the binaries do
 * not link. A double of 2^52 or more is integral already.
 */
static inline double shirudo_trunc(double x)
{
	if (x == 0 || !(x > -0x1p52 && x < 0x1p52))
		return x;
	if (x < 0)
		return -(double)(__s64)-x;
	return (double)(__s64)x;
}

/*
 * The C library's names for them, refused once <stdint.h> has defined
 * them and <stdlib.h> used them for random_r(), so that a later include
 * of either still works. Any other system header that uses them,
 * <netinet/in.h>, <elf.h> or one of OpenSSL's or tpm2-tss's, goes above
 * the first shirudo header.
 */
#pragma GCC poison uint8_t uint16_t uint32_t uint64_t
#pragma GCC poison int8_t int16_t int32_t int64_t

#endif /* SHIRUDO_MISC_H */
