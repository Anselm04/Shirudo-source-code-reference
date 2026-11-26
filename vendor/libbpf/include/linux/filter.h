/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * eBPF instruction constructors libbpf's loader generator emits with.
 * Each one spells out the struct bpf_insn encoding from the UAPI; the
 * two-instruction wide-immediate form follows the ld_imm64 layout.
 */

#ifndef SHIRUDO_VENDOR_LINUX_FILTER_H
#define SHIRUDO_VENDOR_LINUX_FILTER_H

#include <linux/bpf.h>

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code = CODE, .dst_reg = DST, .src_reg = SRC,	\
		.off = OFF, .imm = IMM })

#define BPF_ALU64_REG(OP, DST, SRC) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)
#define BPF_ALU32_REG(OP, DST, SRC) \
	BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)
#define BPF_ALU64_IMM(OP, DST, IMM) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)
#define BPF_ALU32_IMM(OP, DST, IMM) \
	BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_MOV64_REG(DST, SRC) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)
#define BPF_MOV32_REG(DST, SRC) \
	BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_X, DST, SRC, 0, 0)
#define BPF_MOV64_IMM(DST, IMM) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define BPF_MOV32_IMM(DST, IMM) \
	BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_LD_IMM64_RAW_FULL(DST, SRC, OFF1, OFF2, IMM1, IMM2)	\
	BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, SRC, OFF1, IMM1),	\
	BPF_RAW_INSN(0, 0, 0, OFF2, IMM2)
#define BPF_LD_IMM64_RAW(DST, SRC, IMM) \
	BPF_LD_IMM64_RAW_FULL(DST, SRC, 0, 0, (__u32)(IMM), ((__u64)(IMM)) >> 32)
#define BPF_LD_IMM64(DST, IMM) \
	BPF_LD_IMM64_RAW(DST, 0, IMM)
#define BPF_LD_MAP_FD(DST, MAP_FD) \
	BPF_LD_IMM64_RAW_FULL(DST, BPF_PSEUDO_MAP_FD, 0, 0, MAP_FD, 0)
#define BPF_LD_MAP_VALUE(DST, MAP_FD, VALUE_OFF) \
	BPF_LD_IMM64_RAW_FULL(DST, BPF_PSEUDO_MAP_VALUE, 0, 0, MAP_FD, VALUE_OFF)

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
	BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
	BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM) \
	BPF_RAW_INSN(BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, DST, 0, OFF, IMM)

#define BPF_JMP_REG(OP, DST, SRC, OFF) \
	BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)
#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
	BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)
#define BPF_JMP32_REG(OP, DST, SRC, OFF) \
	BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)
#define BPF_JMP32_IMM(OP, DST, IMM, OFF) \
	BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)
#define BPF_JMP_A(OFF) \
	BPF_RAW_INSN(BPF_JMP | BPF_JA, 0, 0, OFF, 0)

#define BPF_EMIT_CALL(FUNC) \
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, ((FUNC) - BPF_FUNC_unspec))
#define BPF_CALL_REL(TGT) \
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, TGT)
#define BPF_EXIT_INSN() \
	BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#endif /* SHIRUDO_VENDOR_LINUX_FILTER_H */
