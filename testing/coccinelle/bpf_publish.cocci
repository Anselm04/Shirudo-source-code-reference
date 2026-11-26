// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// WRITE_ONCE() of a pointer publishes what it points to without ordering
// the stores that filled it, on every kernel: arm64 and riscv64 let a
// reader that follows the pointer see the old contents, and the compiler
// may move the stores after it on any architecture. A release store orders
// them.
#spatch --no-includes --macro-file testing/coccinelle/bpf.macros

virtual report

@r depends on report@
attribute name SEC;
type T;
T *e;
expression x;
position pos;
@@
WRITE_ONCE@pos(x, e)

@script:python depends on report@
e << r.e;
pos << r.pos;
@@
if e.strip() in ("NULL", "0", "(void *)0"):
	cocci.include_match(False)
else:
	coccilib.report.print_report(pos[0],
		"WRITE_ONCE() publishes a pointer unordered: use __atomic_store_n(&x, p, __ATOMIC_RELEASE)")
