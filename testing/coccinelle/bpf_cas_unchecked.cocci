// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A compare-and-swap whose result nobody reads may have failed, on every
// kernel: another CPU changed the value first, and the code goes on as if
// it had won. A failed one also orders nothing.
#spatch --no-includes --macro-file testing/coccinelle/bpf.macros

virtual report

@r depends on report@
attribute name SEC;
identifier cas = {__sync_val_compare_and_swap,
		  __sync_bool_compare_and_swap,
		  __atomic_compare_exchange_n, __atomic_compare_exchange};
position pos;
@@
cas@pos(...);

@script:python depends on report@
pos << r.pos;
@@
coccilib.report.print_report(pos[0],
	"compare-and-swap result ignored: check whether it won")
