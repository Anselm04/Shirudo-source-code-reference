// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "paths.h"
#include "seal.h"
#include "serializer.h"

int serializer_lock_acquire_at(const char *dir, __u32 map_id)
{
	char name[64];
	struct stat st;
	int dir_fd, fd, ret;

	if (!dir || !dir[0] || map_id == 0)
		return -EINVAL;
	ret = seal_mkdir_p(dir, 0700);
	if (ret)
		return ret;
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dir_fd < 0)
		return -errno;
	if (strsprintf(name, sizeof(name), "serializer-map-%u.lock", map_id) < 0) {
		close(dir_fd);
		return -ENAMETOOLONG;
	}
	fd = openat(dir_fd, name, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		ret = -errno;
		close(dir_fd);
		return ret;
	}
	ret = seal_inherit(dir_fd, fd);
	close(dir_fd);
	if (ret) {
		close(fd);
		return ret;
	}
	if (fstat(fd, &st) != 0) {
		ret = -errno;
		close(fd);
		return ret;
	}
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		return -EINVAL;
	}
	/* The open fd owns the lock; callers release it with close(). */
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		ret = errno == EWOULDBLOCK ? -EBUSY : -errno;
		close(fd);
		return ret;
	}
	return fd;
}

int serializer_lock_acquire(__u32 map_id)
{
	return serializer_lock_acquire_at(LOCKS_DIR, map_id);
}

int serializer_new_invocation_id(__u64 *out)
{
	__u64 id;
	__u8 *p = (__u8 *)&id;
	size_t off;

	if (!out)
		return -EINVAL;
	do {
		off = 0;
		while (off < sizeof(id)) {
			ssize_t n = getrandom(p + off, sizeof(id) - off, 0);

			if (n < 0) {
				if (errno == EINTR)
					continue;
				return -errno;
			}
			if (n == 0)
				return -EIO;
			off += (size_t)n;
		}
	} while (id == 0);
	*out = id;
	return 0;
}

int serial_chunk_validate(const struct serial_chunk *c,
			  __u32 want_index,
			  __u32 total_chunks,
			  __u32 page_index,
			  __u64 cursor,
			  __u64 next_cursor,
			  __u64 invocation_id)
{
	if (!c || invocation_id == 0)
		return -EINVAL;
	if (c->magic != SERIAL_MAGIC ||
	    c->version != SERIAL_VERSION)
		return -EBADMSG;
	if (c->chunk_index != want_index || c->total_chunks != total_chunks)
		return -EBADMSG;
	if (c->bytes_in_chunk > SERIAL_CHUNK_PAYLOAD)
		return -EBADMSG;
	if (c->page_index != page_index || c->cursor != cursor ||
	    c->next_cursor != next_cursor ||
	    c->invocation_id != invocation_id)
		return -EBADMSG;
	return 0;
}
