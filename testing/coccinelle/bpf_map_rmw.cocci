// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A load, an add and a store through a value that other CPUs share lose
// updates on every kernel: the value of a map that is not per-CPU, and
// inode, socket and cgroup storage. __sync_fetch_and_add() and its kin
// update it in one instruction. A per-CPU value is left out: it needs the
// atomic only where a second run can start on its CPU before the first one
// ends, which depends on the preemption model and the programs that update
// it, and a counter that one kprobe or tracing program alone updates needs
// none on any kernel. Task storage is left out too, as only its task
// writes it, unless a program writes another task's or runs in a softirq.
#spatch --no-includes --macro-file testing/coccinelle/bpf.macros

virtual report

@initialize:python@
@@
import re

shared = {}
map_def = re.compile(r'struct\s*\{([^}]*)\}\s*(\w+)\s+SEC\(\s*"\.maps"\s*\)')


def shared_maps(path):
	if path not in shared:
		names = set()
		try:
			with open(path) as f:
				for body, name in map_def.findall(f.read()):
					if 'PERCPU' not in body:
						names.add(name)
		except OSError:
			pass
		shared[path] = names
	return shared[path]

@r depends on report exists@
attribute name SEC;
identifier m, p, f;
expression k, e, e2;
type T;
position pos;
@@
(
p = bpf_map_lookup_elem(&m, k);
|
T *p = bpf_map_lookup_elem(&m, k);
)
... when != p = e2
(
p->f@pos++
|
p->f@pos--
|
p->f@pos += e
|
p->f@pos -= e
|
p->f@pos |= e
|
p->f@pos &= e
|
 (*p@pos)++
|
 (*p@pos)--
|
 *p@pos += e
|
 *p@pos -= e
|
 *p@pos |= e
|
 *p@pos &= e
|
 *p@pos = *p + e
|
 *p@pos = *p - e
|
p->f@pos = p->f + e
|
p->f@pos = p->f - e
)

@s depends on report exists@
identifier get = {bpf_inode_storage_get, bpf_sk_storage_get,
		  bpf_cgrp_storage_get};
expression list args;
identifier p, f;
expression e, e2;
type T;
position pos;
@@
(
p = get(args);
|
T *p = get(args);
)
... when != p = e2
(
p->f@pos++
|
p->f@pos--
|
p->f@pos += e
|
p->f@pos -= e
|
p->f@pos |= e
|
p->f@pos &= e
|
p->f@pos = p->f + e
|
p->f@pos = p->f - e
)

@script:python depends on report@
m << r.m;
pos << r.pos;
@@
if m not in shared_maps(pos[0].file):
	cocci.include_match(False)
else:
	coccilib.report.print_report(pos[0],
		"read-modify-write of a shared map value is not atomic: use __sync_fetch_and_add() or its kin")

@script:python depends on report@
pos << s.pos;
@@
coccilib.report.print_report(pos[0],
	"read-modify-write of storage other CPUs share is not atomic: use __sync_fetch_and_add() or its kin")
