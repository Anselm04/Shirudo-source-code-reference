// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where util/upatch_rodata.c finds the .rodata value of a .upatch, with
 * data of DATA_LEN bytes, for loaders of any LEN instructions up to 8 and,
 * at LEN 24, for the gen_loader map create and update with any operands:
 * it reads only the loader and the data, and the value lies in the data.
 */

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/upatch.c"

/* The loader reads instruction immediates as unsigned on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/upatch_rodata.c"
#pragma CPROVER check pop

#define DATA_LEN	48
#define SHAPED_LEN	24

static struct btf_type datasec;

const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id)
{
	bool found;

	return found ? &datasec : NULL;
}

static void op(struct bpf_insn *insn, __u8 code, __u8 dst, __u8 src)
{
	insn->code = code;
	insn->dst_reg = dst;
	insn->src_reg = src;
	insn->off = 0;
}

static void lddw(struct bpf_insn *insn, __u8 dst)
{
	op(insn, BPF_LD | BPF_DW | BPF_IMM, dst, BPF_PSEUDO_MAP_IDX_VALUE);
	insn->imm = 0;
	op(insn + 1, 0, 0, 0);
}

static void sys_bpf(struct bpf_insn *insn, __s32 cmd)
{
	op(insn, BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0);
	insn->imm = cmd;
	lddw(insn + 1, BPF_REG_2);
	op(insn + 3, BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0);
	op(insn + 4, BPF_JMP | BPF_CALL, 0, 0);
	insn[4].imm = BPF_FUNC_sys_bpf;
}

/*
 * The fd copy and value store a map update needs, a map create, the slot
 * it stores its fd in, and the update; every other immediate stays free.
 */
static void gen_loader_shape(struct bpf_insn *insns)
{
	lddw(&insns[0], BPF_REG_2);
	op(&insns[2], BPF_LDX | BPF_W | BPF_MEM, BPF_REG_0, BPF_REG_2);
	lddw(&insns[3], BPF_REG_1);
	op(&insns[5], BPF_STX | BPF_W | BPF_MEM, BPF_REG_1, BPF_REG_0);
	lddw(&insns[6], BPF_REG_0);
	lddw(&insns[8], BPF_REG_1);
	op(&insns[10], BPF_STX | BPF_DW | BPF_MEM, BPF_REG_1, BPF_REG_0);
	sys_bpf(&insns[11], BPF_MAP_CREATE);
	lddw(&insns[16], BPF_REG_1);
	op(&insns[18], BPF_STX | BPF_W | BPF_MEM, BPF_REG_1, BPF_REG_7);
	sys_bpf(&insns[19], BPF_MAP_UPDATE_ELEM);
}

void harness(void)
{
	struct {
		struct bpf_insn insns[LEN];
		__u8 data[DATA_LEN];
	} loader;
	struct rodata_view view = {};
	struct upatch u = {};
	struct btf_type t;
	__u32 id;

	if (LEN == SHAPED_LEN)
		gen_loader_shape(loader.insns);
	u.map = (const __u8 *)&loader;
	u.map_size = sizeof(loader);
	u.hdr.loader_insns_len = sizeof(loader.insns);
	u.hdr.data_off = sizeof(loader.insns);
	u.hdr.data_len = DATA_LEN;
	datasec = t;
	if (find_rodata_data(&u, (const struct btf *)&u, id, &view))
		return;
	__CPROVER_assert(BTF_INFO_KIND(datasec.info) == BTF_KIND_DATASEC &&
			 view.type_id == id && view.size == datasec.size,
			 "the value of the section");
	__CPROVER_assert(view.data_offset <= DATA_LEN &&
			 view.size <= DATA_LEN - view.data_offset &&
			 view.bytes == loader.data + view.data_offset,
			 "inside the data");
}
