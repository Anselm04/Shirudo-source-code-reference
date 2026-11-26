// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Process-level hardening and process-wide memory locking.
 */

#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include <shirudo/misc.h>

#include "harden.h"
#include "log.h"

/*
 * Started with standard input, output or error closed, the process gives
 * that number to the next file it opens, and what it prints lands in
 * that file: point each closed one at /dev/null before anything opens.
 */
void harden_stdio(void)
{
	int fd;

	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
			continue;
		/* The ones below fd are open, so fd is the lowest free. */
		if (open("/dev/null", O_RDWR) != fd)
			_exit(1);
	}
}

/*
 * No host file may name code for the process to load: an OpenSSL
 * configuration file can activate a provider module, and nsswitch.conf
 * can name an NSS module for the host lookups libcurl makes, both
 * dlopen()ed from paths root controls whatever secure-exec mode does to
 * the environment. glibc's own files and dns services answer host
 * lookups without a module, in a static binary too. The personality
 * comes from the caller too: UNAME26 has uname() report a 2.6 release
 * to the tree selector, READ_IMPLIES_EXEC makes later mappings
 * executable. So do the file size and CPU time limits and the interval
 * timers, which exec keeps and with which the kernel would stop the
 * command midway by SIGXFSZ, SIGXCPU or SIGALRM.
 */
int harden_self(void)
{
	static const int signalling[] = { RLIMIT_FSIZE, RLIMIT_CPU };
	static const int timers[] = { ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF };
	struct rlimit no_core = {}, unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	struct itimerval off = {};
	size_t i;

	if (personality(PER_LINUX) < 0) {
		int err = -errno;

		pr_err("hardening: cannot reset the personality: %s",
		       strerror(-err));
		return err;
	}
	for (i = 0; i < ARRAY_SIZE(signalling); i++) {
		if (setrlimit(signalling[i], &unlimited)) {
			int err = -errno;

			pr_err("hardening: cannot reset the resource limits: %s",
			       strerror(-err));
			return err;
		}
	}
	for (i = 0; i < ARRAY_SIZE(timers); i++) {
		if (setitimer(timers[i], &off, NULL)) {
			int err = -errno;

			pr_err("hardening: cannot disarm the interval timers: %s",
			       strerror(-err));
			return err;
		}
	}

	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_PTRACER, 0, 0, 0, 0);
	setrlimit(RLIMIT_CORE, &no_core);
	OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
	__nss_configure_lookup("hosts", "files dns");
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		int err = -errno;

		pr_err("hardening: cannot lock process memory: %s", strerror(-err));
		return err;
	}
	return 0;
}
