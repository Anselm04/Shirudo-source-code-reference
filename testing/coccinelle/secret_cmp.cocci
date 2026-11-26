// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// memcmp() returns at the first difference; compare a secret, or what
// derives from one, with memneq_explicit().

virtual report

@r@
attribute name SEC;
expression A, B, N;
position p;
@@
  memcmp@p(A, B, N)

@script:python depends on report@
p << r.p;
A << r.A;
B << r.B;
@@
import re
secret = re.compile(r"(secret|cred|passw|token|auth|hmac|\bmac\b|_mac\b|sym_key|hmac_key|seed|private|priv_key|shared|\bz\b)", re.I)
if secret.search(A) or secret.search(B):
    coccilib.report.print_report(p[0], "compare a secret with memneq_explicit()")
