// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attempts an unsigned userspace BPF_PROG_LOAD of a trivial program via
 * the raw bpf() syscall and prints the outcome ("loaded" or
 * "errno=<n>"). With shirudo's lsm/bpf hook attached, an unsigned
 * userspace load (kernel == false) must be denied -- the headline
 * enforcement property. No libbpf; raw syscall only.
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#include <shirudo/misc.h>

int main(void)
{
	/* r0 = 0; exit; -- a minimal valid program. */
	struct bpf_insn insns[] = {
		{ .code = 0xb7, .dst_reg = 0, .imm = 0 },	/* BPF_MOV64_IMM */
		{ .code = 0x95 },				/* BPF_EXIT */
	};
	union bpf_attr attr = {};
	int fd;

	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = 2;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64("GPL");

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd >= 0) {
		printf("loaded\n");
		close(fd);
		return 0;
	}
	printf("errno=%d\n", errno);
	return 0;
}
