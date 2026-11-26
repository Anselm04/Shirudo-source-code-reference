// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The stand-in for a fix in the full-chain end-to-end test. It attaches to
 * a function every test kernel has, not to XFS, so that it always loads.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_nanosleep")
int BPF_PROG(xfs_fix)
{
	return 0;
}
