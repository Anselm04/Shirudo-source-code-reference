// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The loader patterns util/upatch_rodata.c matches in a .upatch, for
 * loaders of LEN instructions, each length proofs.list names: every
 * matcher reads only the loader, those that look back from a call only
 * the instructions before it, each reports exactly what it matched, and
 * every map slot it returns indexes the table of maps.
 */

#include "proof.h"

/* The loader reads instruction immediates as unsigned on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/upatch_rodata.c"
#pragma CPROVER check pop

#define UNSET	0xdeadbeefu

static __u32 imm(const struct bpf_insn *insn)
{
	__u32 v;

	memcpy(&v, &insn->imm, sizeof(v));
	return v;
}

static bool lddw(const struct bpf_insn *insn, __u8 reg)
{
	return insn->code == (BPF_LD | BPF_DW | BPF_IMM) &&
	       insn->dst_reg == reg &&
	       insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE;
}

static void lddw_matched(const struct bpf_insn *insns)
{
	__u32 value = UNSET;
	size_t i;
	__u8 reg;

	__CPROVER_assume(i <= LEN);
	if (!loader_lddw(insns, LEN, i, reg, &value)) {
		__CPROVER_assert(value == UNSET, "nothing written");
		return;
	}
	__CPROVER_assert(i + 1 < LEN && lddw(&insns[i], reg) &&
			 !insns[i].imm && !insns[i + 1].code &&
			 value == imm(&insns[i + 1]),
			 "a whole load of the register and its value");
}

static void call_matched(const struct bpf_insn *insns)
{
	__u32 cmd = UNSET, attr = UNSET, attr_size = UNSET;
	size_t i;

	__CPROVER_assume(i <= LEN);
	if (!sys_bpf_call(insns, LEN, i, &cmd, &attr, &attr_size)) {
		__CPROVER_assert(cmd == UNSET && attr_size == UNSET,
				 "no command or size written");
		return;
	}
	__CPROVER_assert(i >= 4 && i < LEN &&
			 insns[i].code == (BPF_JMP | BPF_CALL) &&
			 insns[i].imm == BPF_FUNC_sys_bpf,
			 "a call of sys_bpf()");
	__CPROVER_assert(insns[i - 4].dst_reg == BPF_REG_1 &&
			 cmd == imm(&insns[i - 4]) &&
			 lddw(&insns[i - 3], BPF_REG_2) &&
			 attr == imm(&insns[i - 2]) &&
			 insns[i - 1].dst_reg == BPF_REG_3 &&
			 attr_size == imm(&insns[i - 1]),
			 "the command, attr and size it passes");
}

/*
 * The call at the end of the loader, so that a read past it is one past
 * the loader too.
 */
static void slots_matched(const struct bpf_insn *insns)
{
	__u32 slot = UNSET, source = UNSET, attr, field;

	if (map_create_slot(insns, LEN, 0, LEN, &slot))
		__CPROVER_assert(slot < RODATA_MAPS_MAX, "a slot of the table");
	else
		__CPROVER_assert(slot == UNSET, "nothing written");
	slot = UNSET;
	if (map_update_slot(insns, LEN, LEN, attr, &slot))
		__CPROVER_assert(slot < RODATA_MAPS_MAX, "a slot of the table");
	else
		__CPROVER_assert(slot == UNSET, "nothing written");
	if (!loader_store_source(insns, LEN, LEN, field, &source))
		__CPROVER_assert(source == UNSET, "nothing written");
}

void harness(void)
{
	const struct bpf_insn *insns = any_bytes(LEN * sizeof(*insns));

	lddw_matched(insns);
	call_matched(insns);
	slots_matched(insns);
}
