// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The reader of util/tpm_wire.c, through which its parsers take every field
 * of a TPM structure, for every input of any size and every field size: a
 * read stays inside what is left, keeps the position and what is left
 * summing to the input's end, and a sized field fits its bound.
 */

#include "proof.h"
#include "../../../util/tpm_wire.c"

void harness(void)
{
	size_t left, max, n, name_len;
	const __u8 *start, *data;
	__u8 name[TPM_NAME_LEN];
	struct reader r;
	__u64 v64;
	__u32 v32;
	__u16 v16;
	int which;
	__u8 v8;

	start = any_bytes(left);
	r.p = start;
	r.left = left;
	switch (which) {
	case 0:
		if (get8(&r, &v8))
			return;
		break;
	case 1:
		if (get16(&r, &v16))
			return;
		break;
	case 2:
		if (get32(&r, &v32))
			return;
		break;
	case 3:
		if (get64(&r, &v64))
			return;
		break;
	case 4:
		if (get2b(&r, &data, &n, max))
			return;
		__CPROVER_assert(n <= max && data >= start &&
				 data + n == r.p, "a field inside the input");
		break;
	case 5:
		__CPROVER_assume(max <= TPM_NAME_LEN);
		if (get2b_fixed(&r, name, max))
			return;
		break;
	default:
		if (get_name(&r, name, &name_len))
			return;
		__CPROVER_assert(name_len <= TPM_NAME_LEN, "a name that fits");
		break;
	}
	__CPROVER_assert(r.p >= start &&
			 (size_t)(r.p - start) + r.left == left,
			 "what is left ends with the input");
}
