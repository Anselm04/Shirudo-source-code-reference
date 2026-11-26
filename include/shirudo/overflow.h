/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Integer arithmetic that reports, saturates or rounds instead of
 * wrapping.
 */

#ifndef SHIRUDO_OVERFLOW_H
#define SHIRUDO_OVERFLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <shirudo/compiler.h>
#include <shirudo/misc.h>

static inline bool __must_check __must_check_overflow(bool overflow)
{
	return overflow;
}

/*
 * true when a + b, a - b or a * b, taken over the mathematical integers,
 * does not fit the type d points to. *d holds the result wrapped to that
 * type either way. a and b may be of any integer type and need not match
 * each other or *d.
 */
#define check_add_overflow(a, b, d)					\
	__must_check_overflow(__builtin_add_overflow(a, b, d))
#define check_sub_overflow(a, b, d)					\
	__must_check_overflow(__builtin_sub_overflow(a, b, d))
#define check_mul_overflow(a, b, d)					\
	__must_check_overflow(__builtin_mul_overflow(a, b, d))

/*
 * Sizes that stick at SIZE_MAX once a step does not fit, and stay there
 * through the steps after it, so that the allocation or bound they reach
 * fails rather than come out short.
 */
static inline size_t __must_check size_add(size_t a, size_t b)
{
	size_t bytes;

	if (check_add_overflow(a, b, &bytes))
		return SIZE_MAX;
	return bytes;
}

static inline size_t __must_check size_mul(size_t a, size_t b)
{
	size_t bytes;

	if (check_mul_overflow(a, b, &bytes))
		return SIZE_MAX;
	return bytes;
}

static inline size_t __must_check size_sub(size_t a, size_t b)
{
	size_t bytes;

	if (a == SIZE_MAX || b == SIZE_MAX || check_sub_overflow(a, b, &bytes))
		return SIZE_MAX;
	return bytes;
}

/*
 * n / d rounded up, for n of 0 and up and d of 1 and up, without the
 * n + d - 1 that wraps when n is near the top of its type.
 */
#define DIV_ROUND_UP(n, d) ({						\
	__auto_type __n = (n);						\
	__auto_type __d = (d);						\
									\
	__n / __d + (__n % __d != 0);					\
})

/*
 * The size of *p with count elements in its flexible array member, which
 * has to be an array and not a pointer.
 */
#define __flex_array_size(a, count)					\
	size_mul(sizeof(typeof((a)[0])) +				\
		 BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), \
				   typeof((a)[0]) *)), count)
#define struct_size(p, member, count)					\
	size_add(sizeof(typeof((p)[0])),				\
		 __flex_array_size((p)[0].member, count))

#endif /* SHIRUDO_OVERFLOW_H */
