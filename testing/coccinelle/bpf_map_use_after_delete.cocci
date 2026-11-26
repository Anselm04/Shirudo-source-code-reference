// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon
//
// A hash map element that bpf_map_delete_elem() removes goes back to the
// map's free list at once, without waiting for an RCU grace period, so an
// update on this CPU or another one can take it and fill it with another
// entry while a pointer from an earlier lookup still reads it. RCU keeps
// the memory valid, not its contents, on every kernel. Read or copy what
// is needed before the delete. The rule cannot tell whether two keys are
// equal and takes any delete from the same map; a test of the pointer
// against NULL or another pointer reads nothing and is left alone.
#spatch --no-includes --macro-file testing/coccinelle/bpf.macros

virtual report

@r exists@
attribute name SEC;
identifier m, p, f, fn;
expression k1, k2, e, x, i;
type T;
position pd, pu;
@@
(
p = bpf_map_lookup_elem(&m, k1);
|
T *p = bpf_map_lookup_elem(&m, k1);
)
... when != p = e
bpf_map_delete_elem@pd(&m, k2);
... when != p = e
(
p@pu->f
|
 *p@pu
|
p@pu[i]
|
fn(..., p@pu, ...)
|
x = p@pu
)

@script:python depends on report@
p << r.p;
pd << r.pd;
pu << r.pu;
@@
coccilib.report.print_report(pu[0],
	"%s read after its entry was deleted on line %s: copy what is needed before the delete" % (p, pd[0].line))
