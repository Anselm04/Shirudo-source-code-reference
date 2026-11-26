// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Execs a program in a child with a stack limit too small for the argument
 * pointers, so that the exec fails after its point of no return and the
 * child dies by SIGSEGV with a core dump, and prints how the child ended.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <shirudo/misc.h>

#define EMPTY_ARGS	2500
#define STACK_LIMIT	(16 * 1024)

static void exec_without_stack(const char *path)
{
	struct rlimit stack = { STACK_LIMIT, STACK_LIMIT };
	struct rlimit core = { RLIM_INFINITY, RLIM_INFINITY };
	static char *argv[EMPTY_ARGS + 2];
	char empty[] = "";
	size_t i;

	argv[0] = empty;
	for (i = 1; i <= EMPTY_ARGS; i++)
		argv[i] = empty;
	if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_STACK, &stack)) {
		fprintf(stderr, "setrlimit: %s\n", strerror(errno));
		_exit(2);
	}
	execv(path, argv);
	fprintf(stderr, "execv %s: %s\n", path, strerror(errno));
	_exit(2);
}

int main(int argc, char **argv)
{
	int status;
	pid_t pid;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <program>\n", argv[0]);
		return 2;
	}
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork: %s\n", strerror(errno));
		return 2;
	}
	if (!pid)
		exec_without_stack(argv[1]);
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "waitpid: %s\n", strerror(errno));
		return 2;
	}
	if (WIFSIGNALED(status))
		printf("signal %d\n", WTERMSIG(status));
	else
		printf("exit %d\n", WEXITSTATUS(status));
	return 0;
}
