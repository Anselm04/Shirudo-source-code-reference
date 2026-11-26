// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A return code declared with an error, int ret = -EACCES, is the error
// of every goto or break that leaves without setting one. Once a call's
// result or a 0 has been stored in it, such a jump returns that instead,
// the success of the step before: a search that found nothing, or a
// response that held nothing, passes. A function that stores a positive
// value in it answers yes or no, and its 0 is an answer.

virtual report

@r exists@
attribute name SEC;
identifier ret, L, f, C;
expression E1;
expression list es;
type T;
position p1, p2, p3;
@@
  T ret@p1 = -C;
  ... when != ret = E1
(
  ret@p2 = f(es);
|
  ret@p2 = 0;
)
  ... when != ret = E1
(
  goto@p3 L;
|
  break@p3;
)
  ... when != ret = E1
  return ret;

@script:python depends on report@
p1 << r.p1;
p2 << r.p2;
p3 << r.p3;
ret << r.ret;
C << r.C;
@@
import re
name = re.compile(r"\b%s\b" % re.escape(ret))
lines = open(p1[0].file).read().split("\n")
def indent(l):
    return len(l.expandtabs(8)) - len(l.expandtabs(8).lstrip())
# The test that leads to the jump, from the if or else that opens it: a
# jump on a test of ret itself leaves with what ret holds on purpose.
opener = re.compile(r"^\s*(\}\s*)?(if|else)\b")
at = int(p3[0].line) - 1
guard = [lines[at]]
for i in range(at - 1, 0, -1):
    if opener.match(guard[-1]) and indent(guard[-1]) < indent(lines[at]) \
       or opener.match(lines[at]) or not indent(lines[i]):
        break
    guard.append(lines[i])
end = next((i for i in range(int(p1[0].line), len(lines))
            if lines[i] == "}"), len(lines))
answers = re.search(r"\b%s\s*=\s*[1-9]" % re.escape(ret),
                    "\n".join(lines[int(p1[0].line):end]))
if re.match(r"^E[A-Z0-9]+$", C) and not answers and \
   not any(name.search(l) for l in guard):
    coccilib.report.print_report(p3[0], "leaves with what line %s stored in %s, not the -%s it was declared with" % (p2[0].line, ret, C))
