// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where util/upatch_rodata.c finds the BTF of a .upatch, for loaders of
 * LEN instructions, each length proofs.list names, and data of DATA_LEN
 * bytes: it reads only the loader and the data, and the BTF it returns
 * lies inside the data.
 */

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/upatch.c"

/* The loader reads instruction immediates as unsigned on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/upatch_rodata.c"
#pragma CPROVER check pop

#define DATA_LEN	24

void harness(void)
{
	struct {
		struct bpf_insn insns[LEN];
		__u8 data[DATA_LEN];
	} loader;
	struct upatch u = {};
	__u32 off, size;

	u.map = (const __u8 *)&loader;
	u.map_size = sizeof(loader);
	u.hdr.loader_insns_len = sizeof(loader.insns);
	u.hdr.data_off = sizeof(loader.insns);
	u.hdr.data_len = DATA_LEN;
	if (loader_btf(&u, &off, &size))
		return;
	__CPROVER_assert(off <= DATA_LEN && size <= DATA_LEN - off,
			 "BTF inside the data");
}
