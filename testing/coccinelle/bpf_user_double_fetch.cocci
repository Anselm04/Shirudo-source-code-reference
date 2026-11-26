// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// User memory can change between two reads of the same address, on every
// kernel, as another thread writes it meanwhile: a decision taken on the
// first copy and an action on the second check different data. Read it
// once, into memory of the program's own.
#spatch --no-includes --macro-file testing/coccinelle/bpf.macros

virtual report

@r depends on report@
attribute name SEC;
identifier rd1 = {bpf_probe_read_user, bpf_probe_read_user_str,
		  bpf_copy_from_user, bpf_copy_from_user_str,
		  bpf_copy_from_user_task, bpf_copy_from_user_task_str};
identifier rd2 = {bpf_probe_read_user, bpf_probe_read_user_str,
		  bpf_copy_from_user, bpf_copy_from_user_str,
		  bpf_copy_from_user_task, bpf_copy_from_user_task_str};
expression d1, d2, n1, n2, src, e;
position pos;
@@
rd1(d1, n1, src, ...)
... when != src = e
rd2@pos(d2, n2, src, ...)

@script:python depends on report@
pos << r.pos;
@@
coccilib.report.print_report(pos[0],
	"user memory read twice: it can change in between; read it once")
