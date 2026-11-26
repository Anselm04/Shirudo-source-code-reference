// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * append_line() and last_line_end() of util/io.c, which add a record to
 * the eventlog, the tree eventlog and the outcomes record, on every file of
 * LEN bytes and every line of up to LINE_MAX: a line holding a
 * line break or a NUL is refused with the file unchanged; else the file is
 * cut back to its last line break and the line and one line break follow;
 * a failed write is cut back to that line break again.
 */

/*
 * The file's length is a constant to CBMC: last_line_end() reads it into
 * 4 KiB at offsets that would otherwise be symbolic.
 */
#define OLD_MAX		LEN
#define LINE_MAX	3
#define PROOF_FILE	(OLD_MAX + LINE_MAX + 1)

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/io.c"

static bool stat_fails, sync_fails;
static int first_write;		/* 0 any count, else a failure's errno */
static size_t first_count;
static int writes;

void pr_warn(const char *fmt, ...)
{
}

/* The size set either way, so that CBMC keeps it a constant past the call. */
int fstat(int fd, struct stat *st)
{
	st->st_size = (off_t)proof_file_len;
	if (stat_fails) {
		errno = EIO;
		return -1;
	}
	return 0;
}

int ftruncate(int fd, off_t len)
{
	__CPROVER_assert(len >= 0 && (size_t)len <= proof_file_len,
			 "a file cut, never grown");
	proof_file_len = (size_t)len;
	return 0;
}

/*
 * The first write fails with EINTR or EIO, takes nothing, or takes any
 * part; any later one takes all it is given.
 */
ssize_t write(int fd, const void *buf, size_t n)
{
	size_t count = n;

	if (!writes++) {
		if (first_write) {
			errno = first_write;
			return -1;
		}
		__CPROVER_assume(first_count <= n);
		count = first_count;
	}
	__CPROVER_assert(count <= n && proof_file_len + count <= PROOF_FILE,
			 "a write inside the model");
	memcpy(proof_file + proof_file_len, buf, count);
	proof_file_len += count;
	return (ssize_t)count;
}

int fsync(int fd)
{
	if (sync_fails) {
		errno = EIO;
		return -1;
	}
	return 0;
}

void harness(void)
{
	bool any_stat, any_sync, newline;
	size_t old, len, end, i, any_count;
	char was[OLD_MAX + 1], *line;
	int any_write, ret;

	proof_file_open();
	old = OLD_MAX;
	__CPROVER_assume(len <= LINE_MAX);
	proof_file_len = old;
	for (i = 0; i < OLD_MAX; i++)
		was[i] = proof_file[i];
	stat_fails = any_stat;
	sync_fails = any_sync;
	first_write = any_write;
	first_count = any_count;
	__CPROVER_assume(!first_write || first_write == EINTR ||
			 first_write == EIO);
	line = any_bytes(LINE_MAX);
	newline = len && line[len - 1] == '\n';
	ret = append_line(3, "log", line, len);
	if (memchr(line, '\n', len - newline) ||
	    memchr(line, '\0', len - newline)) {
		__CPROVER_assert(ret == -EINVAL && proof_file_len == old,
				 "a line holding a line break or a NUL refused");
		return;
	}
	if (stat_fails) {
		__CPROVER_assert(ret == -EIO && proof_file_len == old,
				 "a file it cannot stat left alone");
		return;
	}
	end = lines_len(was, old);
	if (ret) {
		__CPROVER_assert((first_write == EIO && ret == -EIO) ||
				 (!first_write && !first_count && ret == -EIO) ||
				 (sync_fails && ret == -EIO),
				 "a failed write or sync its error");
		__CPROVER_assert(proof_file_len == end,
				 "and the file cut back to its last line break");
		return;
	}
	__CPROVER_assert(proof_file_len == end + len - newline + 1,
			 "the file to its last line break, the line and one");
	for (i = 0; i < end; i++)
		__CPROVER_assert(proof_file[i] == was[i],
				 "the whole lines before kept");
	for (i = 0; i < len - newline; i++)
		__CPROVER_assert(proof_file[end + i] == line[i],
				 "then the line");
	__CPROVER_assert(proof_file[end + len - newline] == '\n',
			 "then one line break");
}
