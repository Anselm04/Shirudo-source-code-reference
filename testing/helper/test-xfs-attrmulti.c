// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Issues XFS_IOC_ATTRMULTI_BY_HANDLE with no operations on the file named
 * and prints the errno it fails with, or 0: XFS itself refuses the empty
 * handle with EINVAL, so EACCES comes from an LSM.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/types.h>

struct handle_req {
	__u32 fd;
	void *path;
	__u32 oflags;
	void *ihandle;
	__u32 ihandlen;
	void *ohandle;
	__u32 *ohandlen;
};

struct attrmulti_req {
	struct handle_req hreq;
	__u32 opcount;
	void *ops;
};

#define XFS_IOC_ATTRMULTI_BY_HANDLE	_IOW('X', 123, struct attrmulti_req)

int main(int argc, char **argv)
{
	struct attrmulti_req req = {};
	int fd, ret;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <file on XFS>\n", argv[0]);
		return 2;
	}
	fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", argv[1], strerror(errno));
		return 2;
	}
	ret = ioctl(fd, XFS_IOC_ATTRMULTI_BY_HANDLE, &req);
	printf("%d\n", ret < 0 ? errno : 0);
	close(fd);
	return 0;
}
