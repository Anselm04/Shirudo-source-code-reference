// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "decoder.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[16]);
	__type(value, __u64);
} execs SEC(".maps");

const struct decoder_manifest execs_decoder SEC(".rodata") = {
	.magic = DECODER_MANIFEST_MAGIC,
	.version = UPATCH_DECODER_VERSION,
	.language = UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = UPATCH_DECODER_EXPORT_LOG,
	.upatch = "exec-count",
	.map = "execs",
	.source = "decoders/execs.lua",
	.entrypoint = "decode",
};

SEC("tp_btf/sched_process_exec")
int BPF_PROG(count_exec, struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	char comm[16] = {};
	__u64 zero = 0, *n;

	bpf_get_current_comm(comm, sizeof(comm));
	n = bpf_map_lookup_elem(&execs, comm);
	if (!n) {
		bpf_map_update_elem(&execs, comm, &zero, BPF_NOEXIST);
		n = bpf_map_lookup_elem(&execs, comm);
	}
	if (n)
		__sync_fetch_and_add(n, 1);
	return 0;
}
