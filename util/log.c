// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "log.h"

#define LOG_MSG_MAX	8192

static bool to_stderr = true;

bool log_stream_is(const char *stream, __u64 dev, __u64 ino)
{
	const char *colon;
	__u64 d, i;

	if (!stream)
		return false;
	colon = strchr(stream, ':');
	if (!colon)
		return false;
	return !parse_u64(stream, colon - stream, ~0ULL, &d) &&
	       !parse_u64(colon + 1, strlen(colon + 1), ~0ULL, &i) &&
	       d == dev && i == ino;
}

/*
 * systemd connects a service's standard error to the journal and names
 * that stream in JOURNAL_STREAM. A message sent to syslog and written
 * there too is in the journal twice. Without /dev/log syslog(3) drops
 * the message, so the copy on standard error stays then.
 */
static bool stderr_repeats_syslog(void)
{
	struct stat st;

	return !fstat(STDERR_FILENO, &st) &&
	       log_stream_is(getenv("JOURNAL_STREAM"), st.st_dev, st.st_ino) &&
	       !access("/dev/log", F_OK);
}

void log_init(void)
{
	openlog("shirudo", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
	to_stderr = !stderr_repeats_syslog();
}

/*
 * A message can carry text from outside, a registry's error body or a
 * name from a package, and with it terminal escape sequences or line
 * breaks that forge records. Keep printable ASCII, double a backslash and
 * write every other byte as a backslash and three octal digits.
 */
static void escape(char *dst, size_t cap, const char *src)
{
	size_t n = 0;

	for (; *src && n + 5 <= cap; src++) {
		__u8 c = *src;

		if (c == '\\') {
			dst[n++] = '\\';
			dst[n++] = '\\';
		} else if (c >= 0x20 && c < 0x7f) {
			dst[n++] = c;
		} else {
			dst[n++] = '\\';
			dst[n++] = '0' + (c >> 6);
			dst[n++] = '0' + ((c >> 3) & 7);
			dst[n++] = '0' + (c & 7);
		}
	}
	dst[n] = '\0';
}

/*
 * Callers report a failure and then return -errno; syslog(3) and stdio
 * may change errno on the way (no /dev/log in an early initrd), so it
 * is kept for them.
 */
static __printf(2, 0) void emit(int priority, const char *fmt, va_list ap)
{
	char msg[LOG_MSG_MAX], out[4 * LOG_MSG_MAX + 1];
	int saved_errno = errno;

	if (vstrsprintf(msg, sizeof(msg), fmt, ap) < 0 &&
	    strscpy(msg, fmt, sizeof(msg)) < 0)
		memcpy(msg + sizeof(msg) - 4, "...", 4);
	escape(out, sizeof(out), msg);
	syslog(priority, "%s", out);
	if (to_stderr)
		fprintf(stderr, "%s\n", out);
	errno = saved_errno;
}

#define PR_DEFINE(name, prio)					\
	void name(const char *fmt, ...)				\
	{							\
		va_list ap;					\
		va_start(ap, fmt);				\
		emit((prio), fmt, ap);				\
		va_end(ap);					\
	}

PR_DEFINE(pr_err,   LOG_ERR)
PR_DEFINE(pr_warn,  LOG_WARNING)
PR_DEFINE(pr_info,  LOG_INFO)
PR_DEFINE(pr_audit, LOG_NOTICE)
