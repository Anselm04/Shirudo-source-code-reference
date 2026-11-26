// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// Test a sum or a product for overflow with the helpers of
// <shirudo/overflow.h>, not by hand against the limit or after the fact.

virtual report

@r@
attribute name SEC;
expression A, B, C;
identifier M = {SIZE_MAX, UINT64_MAX, UINT32_MAX, UINT16_MAX, UINT8_MAX,
		INT64_MAX, INT32_MAX, INT_MAX, LONG_MAX, SSIZE_MAX, UINT_MAX,
		ULONG_MAX, U64_MAX, U32_MAX, U16_MAX};
binary operator op = {>, >=, <, <=};
position p;
@@
(
  A op@p M - B
|
  M - B op@p A
|
  A op@p M / B
|
  M / B op@p A
|
  A op@p (M - B) / C
|
  A + B <@p A
|
  A + B <@p B
)

@script:python depends on report@
p << r.p;
@@
# BPF code is bounded by the verifier and has no <shirudo/overflow.h>.
f = p[0].file
if not f.startswith(("bpf/", "upatches/")) and \
   p[0].current_element not in ("size_add", "size_mul", "size_sub"):
    coccilib.report.print_report(p[0], "use check_add_overflow(), check_mul_overflow() or the size helpers")
