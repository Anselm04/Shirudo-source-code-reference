// SPDX-License-Identifier: BSD-2-Clause
static volatile int sink;
__attribute__((noinline, used)) int fooFunc(int value) { return value + 1; }
__attribute__((noinline, used)) int barFunc(int value) { return value + 2; }
__attribute__((noinline, used)) int notTarget(int value) { return value + 3; }
int main(void)
{
	sink = fooFunc(1) + barFunc(2) + notTarget(3);
	return sink == 0;
}
