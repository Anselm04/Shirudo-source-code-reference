// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Execs a program in a child that shares this process's root and working
 * directory, as clone(CLONE_FS) leaves them, while this process waits,
 * and exits as the child did, or with 126 when its exec failed.
 */

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
	int status;
	long pid;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <program> [<argument>...]\n",
			argv[0]);
		return 2;
	}
	pid = syscall(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0) {
		fprintf(stderr, "clone: %s\n", strerror(errno));
		return 2;
	}
	if (!pid) {
		execv(argv[1], argv + 1);
		fprintf(stderr, "execv %s: %s\n", argv[1], strerror(errno));
		_exit(126);
	}
	if (waitpid((pid_t)pid, &status, 0) < 0) {
		fprintf(stderr, "waitpid: %s\n", strerror(errno));
		return 2;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
