// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The address of a local, stored through a pointer the caller passed in,
// stays in the caller's object when the function returns: the object then
// points into a dead frame, which whoever reads the member next takes for
// what it was told. That holds for a member at any depth, an element and
// *out alike, and for the address of a local's member or element as for
// the local's own. Hand a callback a context of the function's own
// instead, or clear the member on every path out. A pointer declared
// outside a block that keeps the address of a local of the block points
// at storage just as dead once the block ends: read it in the block only.

virtual report

@initialize:python@
@@
import re

callers = set()

# A static local outlives the call; its declaration says so ahead of its
# name, on the line of the name or on the ones the declaration began on.
def is_static(d, l):
    with open(d[0].file) as f:
        lines = f.read().splitlines()
    at = int(d[0].line) - 1
    decl = re.split(r"\b%s\b" % re.escape(l), lines[at])[0]
    while at > 0 and not re.search(r"[;{}]\s*$|^\s*$", lines[at - 1]):
        at -= 1
        decl = lines[at] + " " + decl
    return "static" in decl.split()

def is_array(d, l):
    with open(d[0].file) as f:
        line = f.read().splitlines()[int(d[0].line) - 1]
    return re.search(r"\b%s\s*\[" % re.escape(l), line) is not None

def past_block(pos, q, l):
    coccilib.report.print_report(pos[0], "%s keeps the address of the local %s past its block" % (q, l))

# The pointer a store goes through: p of p->a.b, p->a[i], (*p).a and *p.
# The pointer itself is a variable of the frame, which dies with it.
def escape(fp, d, pos, lhs, l):
    lhs = re.sub(r"\s+", "", lhs)
    m = re.match(r"^[*(]*(\w+)", lhs)
    if not m or m.group(1) == lhs:
        return
    if (fp[0].file, fp[0].line, m.group(1)) in callers and not is_static(d, l):
        coccilib.report.print_report(pos[0], "%s keeps the address of the local %s past the return" % (lhs, l))

// A pointer that came in as a parameter, or was taken from one.
@owner@
attribute name SEC;
identifier f, p;
type T;
position fp;
@@
  f@fp(..., T *p, ...) { ... }

@script:python@
fp << owner.fp;
p << owner.p;
@@
callers.add((fp[0].file, fp[0].line, p))

@alias@
identifier f, p, q;
type T, T1;
position fp;
@@
  f@fp(..., T1 q, ...)
  {
  ... when any
(
  T *p = q;
|
  T *p = (T *)q;
)
  ... when any
  }

@script:python@
fp << alias.fp;
p << alias.p;
@@
callers.add((fp[0].file, fp[0].line, p))

// A cast in the pattern also matches the store without one.
@array exists@
identifier f, l, m;
type T, T2;
expression LHS, E, E2;
position fp, d, pos;
@@
  f@fp(...)
  {
  ... when any
(
  T l@d[...];
|
  T l@d[...] = ...;
)
  ... when any
(
  LHS@pos = (T2)l;
|
  LHS@pos = (T2)&l[...];
|
  LHS@pos = (T2)&l[...].m;
|
  LHS@pos = l + E2;
)
  ... when != LHS = E
  }

@script:python depends on report@
fp << array.fp;
d << array.d;
pos << array.pos;
lhs << array.LHS;
l << array.l;
@@
escape(fp, d, pos, lhs, l)

@scalar exists@
identifier f, l, m, m2;
type T, T2;
expression LHS, E;
position fp, d, pos;
@@
  f@fp(...)
  {
  ... when any
(
  T l@d;
|
  T l@d = ...;
)
  ... when any
(
  LHS@pos = (T2)&l;
|
  LHS@pos = (T2)&l.m;
|
  LHS@pos = (T2)&l.m.m2;
)
  ... when != LHS = E
  }

@script:python depends on report@
fp << scalar.fp;
d << scalar.d;
pos << scalar.pos;
lhs << scalar.LHS;
l << scalar.l;
@@
escape(fp, d, pos, lhs, l)

// A pointer declared outside a block, pointed at a local of the block and
// read once the block has ended, on its last pass or after a jump out.
@block exists@
identifier l, q;
type T, T1;
expression E, E0, E2;
position d, pos, pv, u;
@@
(
  T1 *q;
|
  T1 *q = E0;
|
  T1 *q[...];
|
  T1 *q[...] = E0;
)
  ... when any
  {
  ... when any
(
  T l@d[...];
|
  T l@d[...] = ...;
|
  T l@d;
|
  T l@d = ...;
)
  ... when any
(
  q@pos = &l;
|
  q[...]@pos = &l;
|
  q@pv = l;
|
  q@pv = &l[...];
|
  q[...]@pv = l;
)
  ... when != q = E
  }
  ... when != q = E
(
  q = E2
|
  q[...] = E2
|
  q@u
)

// u is bound only where q is read after the block, not set again.
@script:python depends on report@
d << block.d;
pos << block.pos;
u << block.u;
q << block.q;
l << block.l;
@@
if not is_static(d, l):
    past_block(pos, q, l)

// Only an array decays to its address.
@script:python depends on report@
d << block.d;
pv << block.pv;
u << block.u;
q << block.q;
l << block.l;
@@
if is_array(d, l) and not is_static(d, l):
    past_block(pv, q, l)
