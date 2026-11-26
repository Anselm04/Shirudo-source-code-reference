// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * on_pcr() of util/attest.c, which stores each PCR value of a target's
 * evidence, for every index and value text: it stores only a 64-digit hex
 * value, as the bytes it spells, under one of the 24 PCRs, marks that one
 * and leaves the others, and a refusal marks nothing.
 */

#include "proof.h"
#include "../../../util/hex.c"
#include "../../../util/attest.c"

static struct parse p;

static char any_char(void)
{
	char c;

	return c;
}

static __u8 hex_value(char hi, char lo)
{
	return hex_nibble(hi) << 4 | hex_nibble(lo);
}

void harness(void)
{
	__u8 other_was[32];
	__u32 had, other;
	__s64 index;
	size_t i;

	p.pcr_have = had;
	p.pcr_index = index;
	for (i = 0; i + 1 < sizeof(p.pcr_value_hex); i++)
		p.pcr_value_hex[i] = any_char();
	__CPROVER_assume(other < 24 && other != index);
	for (i = 0; i < 32; i++)
		p.pcrs[other][i] = other_was[i];
	if (on_pcr(&p)) {
		__CPROVER_assert(p.pcr_have == had, "a refusal marks nothing");
		return;
	}
	__CPROVER_assert(index >= 0 && index < 24 &&
			 p.pcr_have == (had | 1u << index),
			 "one of the 24 PCRs marked");
	__CPROVER_assert(strlen(p.pcr_value_hex) == 64,
			 "a SHA-256 value in hex");
	for (i = 0; i < 32; i++) {
		__CPROVER_assert(p.pcrs[index][i] ==
				 hex_value(p.pcr_value_hex[2 * i],
					   p.pcr_value_hex[2 * i + 1]),
				 "stored under its index, as its digits spell");
		__CPROVER_assert(p.pcrs[other][i] == other_was[i],
				 "the other PCRs as they were");
	}
}
