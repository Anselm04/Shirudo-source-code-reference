// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A digest fed two strings in a row, each by its strlen(), takes "ab"
// and "c" for "a" and "bc": nothing of what is hashed says where the
// first ends, so two inputs that differ share one digest. Feed a string
// with its terminator, strlen() + 1, put its length ahead of it, or
// something no string holds between the two.

virtual report

@initialize:python@
@@
import re

UPDATE = r"\b(?:sha256_update|EVP_Digest(?:Sign|Verify)?Update|EVP_MAC_update|HMAC_Update|SHA256_Update|SHA1_Update)\s*\("

def message(p, a, b):
    coccilib.report.print_report(p[0], "%s is hashed right after %s, each by its strlen() alone" % (b, a))

# The digest calls of an expression, in the order it runs them: the
# context each feeds, and the string it feeds by strlen() alone, if any.
def updates(text):
    found = []
    for m in re.finditer(UPDATE, text):
        depth, args, start = 0, [], m.end()
        for i in range(m.end(), len(text)):
            c = text[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                if depth == 0:
                    args.append(text[start:i].strip())
                    break
                depth -= 1
            elif c == "," and depth == 0:
                args.append(text[start:i].strip())
                start = i + 1
        if len(args) != 3:
            continue
        counted = re.sub(r"\s", "", args[2]) == "strlen(%s)" % re.sub(r"\s", "", args[1])
        found.append((re.sub(r"\s", "", args[0]), args[1] if counted else None))
    return found

@seq exists@
attribute name SEC;
expression C, A, B;
identifier f = {sha256_update, EVP_DigestUpdate, EVP_DigestSignUpdate,
		EVP_DigestVerifyUpdate, EVP_MAC_update, HMAC_Update,
		SHA256_Update, SHA1_Update};
position p;
@@
  f(C, A, strlen(A))
  ... when != f(C, ...)
  f@p(C, B, strlen(B))

@script:python depends on report@
p << seq.p;
A << seq.A;
B << seq.B;
@@
message(p, A, B)

// Two calls one condition runs in turn, which is a single node to the
// path above.
@both@
expression E1, E2;
position p;
@@
(
  E1 ||@p E2
|
  E1 &&@p E2
)

@script:python depends on report@
p << both.p;
E1 << both.E1;
E2 << both.E2;
@@
left, right = updates(E1), updates(E2)
if left and right and left[-1][0] == right[0][0] and left[-1][1] and right[0][1]:
    message(p, left[-1][1], right[0][1])

@pair@
expression A, B;
position p;
@@
  sha256_2@p(A, strlen(A), B, strlen(B), ...)

@script:python depends on report@
p << pair.p;
A << pair.A;
B << pair.B;
@@
message(p, A, B)
