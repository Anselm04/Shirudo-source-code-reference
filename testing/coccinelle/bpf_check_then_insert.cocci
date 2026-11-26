// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Looking a key up and inserting it when it is missing races with another
// CPU doing the same, on every kernel: both find nothing, and the later
// BPF_ANY update overwrites what the first stored. BPF_NOEXIST inserts only
// when the key is still missing and returns -EEXIST otherwise.
#spatch --no-includes --macro-file testing/coccinelle/bpf.macros

virtual report

@r depends on report@
attribute name SEC;
identifier m, p;
expression k, v, e2;
type T;
position pos;
@@
(
if (!bpf_map_lookup_elem(&m, k)) {
  ...
  bpf_map_update_elem@pos(&m, k, v, \(BPF_ANY\|0\));
  ...
}
|
p = bpf_map_lookup_elem(&m, k);
... when != p = e2
if (!p) {
  ...
  bpf_map_update_elem@pos(&m, k, v, \(BPF_ANY\|0\));
  ...
}
|
T *p = bpf_map_lookup_elem(&m, k);
... when != p = e2
if (!p) {
  ...
  bpf_map_update_elem@pos(&m, k, v, \(BPF_ANY\|0\));
  ...
}
)

@script:python depends on report@
pos << r.pos;
@@
coccilib.report.print_report(pos[0],
	"insert after a failed lookup races with other CPUs: update with BPF_NOEXIST")
