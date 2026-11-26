// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The integers util/upatch_rodata.c reads from the .rodata of a .upatch by
 * their BTF encoding, for every encoding and value of up to 8 bytes: it
 * reads only the integer's bytes, and the value it returns is the
 * integer's bits, least significant first, zero- or sign-extended.
 */

#include "proof.h"
#include "../../../util/upatch_rodata.c"

/* Bit b of the bytes, counted from the least significant of the first. */
static bool bit_at(const __u8 *bytes, __u32 b)
{
	return bytes[b / 8] >> (b % 8) & 1;
}

static void value_of_bits(__u64 value, const __u8 *bytes, __u32 off,
			  __u32 bits, bool is_signed)
{
	__u32 i;

	for (i = 0; i < 64; i++) {
		bool want = i < bits ? bit_at(bytes, off + i) :
			    is_signed && bit_at(bytes, off + bits - 1);

		__CPROVER_assert((value >> i & 1) == want,
				 "each bit of the value from its place");
	}
}

void harness(void)
{
	struct {
		struct btf_type t;
		__u32 enc;
	} it;
	bool is_signed, is_bool;
	__u32 bits, size;
	__u64 value;
	__u8 *bytes;

	__CPROVER_assume(size <= sizeof(value));
	bytes = any_bytes(size);
	if (btf_integer(&it.t, bytes, size, &value, &is_signed, &is_bool))
		return;
	bits = BTF_INT_BITS(it.enc);
	__CPROVER_assert(it.t.size && it.t.size <= size && bits &&
			 BTF_INT_OFFSET(it.enc) + bits <= it.t.size * 8,
			 "bits inside the integer's bytes");
	value_of_bits(value, bytes, BTF_INT_OFFSET(it.enc), bits, is_signed);
}
