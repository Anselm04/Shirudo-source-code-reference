// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "decoder.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} backend_log SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} backend_metric SEC(".maps");

const struct decoder_manifest log_decoder SEC(".rodata") = {
	.magic = DECODER_MANIFEST_MAGIC,
	.version = UPATCH_DECODER_VERSION,
	.language = UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = UPATCH_DECODER_EXPORT_LOG,
	.upatch = "shirudo-test-otel-backend",
	.map = "backend_log",
	.source = "decoders/log.lua",
	.entrypoint = "decode",
};

const struct decoder_manifest metric_decoder SEC(".rodata") = {
	.magic = DECODER_MANIFEST_MAGIC,
	.version = UPATCH_DECODER_VERSION,
	.language = UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "shirudo-test-otel-backend",
	.map = "backend_metric",
	.source = "decoders/metric.lua",
	.entrypoint = "decode",
};

SEC("fentry/do_nanosleep")
int BPF_PROG(probe)
{
	return 0;
}
