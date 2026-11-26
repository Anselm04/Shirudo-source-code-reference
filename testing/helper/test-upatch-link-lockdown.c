// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Check that an untrusted caller cannot take hold of a pinned upatch link,
 * by its pin or by its id, to keep it attached or to detach or update it.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

static long sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main(int argc, char **argv)
{
	int pin_errno = 0, id_errno = 0, links = 0;
	union bpf_attr attr = {};
	__u32 id = 0;
	long fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <pinned-link>\n", argv[0]);
		return 2;
	}
	attr.pathname = (__u64)(uintptr_t)argv[1];
	fd = sys_bpf(BPF_OBJ_GET, &attr);
	if (fd >= 0) {
		close((int)fd);
		fprintf(stderr, "BPF_OBJ_GET of %s was allowed\n", argv[1]);
		return 1;
	}
	pin_errno = errno;
	for (;;) {
		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (sys_bpf(BPF_LINK_GET_NEXT_ID, &attr))
			break;
		id = attr.next_id;
		memset(&attr, 0, sizeof(attr));
		attr.link_id = id;
		fd = sys_bpf(BPF_LINK_GET_FD_BY_ID, &attr);
		if (fd >= 0) {
			close((int)fd);
			fprintf(stderr, "BPF_LINK_GET_FD_BY_ID %u was allowed\n",
				id);
			return 1;
		}
		if (id_errno && errno != id_errno) {
			fprintf(stderr, "link %u: errno=%d after errno=%d\n",
				id, errno, id_errno);
			return 1;
		}
		id_errno = errno;
		links++;
	}
	printf("pin_errno=%d id_errno=%d links=%d\n", pin_errno, id_errno,
	       links);
	return pin_errno == EACCES && id_errno == EACCES && links ? 0 : 1;
}
