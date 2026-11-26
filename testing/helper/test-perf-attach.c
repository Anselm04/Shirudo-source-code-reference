// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attach a loaded kprobe-type program to a perf event of the caller's
 * own through PERF_EVENT_IOC_SET_BPF, the legacy attach path that
 * never passes through bpf(). The event is a uprobe on this executable,
 * which needs no kprobe support; whether it fires is beside the point.
 * With --kprobe-multi, create a kprobe multi link for the program instead.
 * Prints "attached" or "errno=<n>". No libbpf.
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>

#include <shirudo/string.h>

static long bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int uprobe_type(void)
{
	char buf[16];
	__u64 type;
	ssize_t n;
	int fd;

	fd = open("/sys/bus/event_source/devices/uprobe/type",
		  O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n <= 0 || parse_u64(buf, digits(buf, n), INT_MAX, &type))
		return -1;
	return type;
}

/* The file offset of the first executable segment, where a probe may sit. */
static long exec_offset(const char *path)
{
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	long off = -1;
	int fd, i;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (read(fd, &eh, sizeof(eh)) != sizeof(eh))
		goto out;
	for (i = 0; i < eh.e_phnum; i++) {
		if (pread(fd, &ph, sizeof(ph),
			  eh.e_phoff + (off_t)i * eh.e_phentsize) != sizeof(ph))
			break;
		if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
			off = (long)ph.p_offset + 64;
			break;
		}
	}
out:
	close(fd);
	return off;
}

static int find_prog(const char *want, __u32 *id_out)
{
	union bpf_attr attr;
	__u32 id = 0;

	for (;;) {
		struct bpf_prog_info info;
		int fd;

		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (bpf(BPF_PROG_GET_NEXT_ID, &attr))
			return -1;
		id = attr.next_id;
		memset(&attr, 0, sizeof(attr));
		attr.prog_id = id;
		fd = (int)bpf(BPF_PROG_GET_FD_BY_ID, &attr);
		if (fd < 0)
			continue;
		memset(&info, 0, sizeof(info));
		memset(&attr, 0, sizeof(attr));
		attr.info.bpf_fd = (__u32)fd;
		attr.info.info_len = sizeof(info);
		attr.info.info = (__u64)(size_t)&info;
		if (!bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) &&
		    info.type == BPF_PROG_TYPE_KPROBE &&
		    (!want || !strcmp(info.name, want))) {
			*id_out = id;
			return fd;
		}
		close(fd);
	}
}

static int link_kprobe_multi(const char *want)
{
	const char *sym = "vfs_read";
	union bpf_attr attr = {};
	__u32 id = 0;
	int prog_fd, link_fd;

	prog_fd = find_prog(want, &id);
	if (prog_fd < 0) {
		fprintf(stderr, "no loaded kprobe-type program\n");
		return 2;
	}
	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_KPROBE_MULTI;
	attr.link_create.kprobe_multi.syms = (__u64)(size_t)&sym;
	attr.link_create.kprobe_multi.cnt = 1;
	link_fd = (int)bpf(BPF_LINK_CREATE, &attr);
	if (link_fd >= 0) {
		printf("attached prog_id=%u\n", id);
		return 0;
	}
	printf("errno=%d\n", errno);
	return 0;
}

int main(int argc, char **argv)
{
	struct perf_event_attr pe;
	char self[4096];
	__u32 id = 0;
	ssize_t n;
	long off;
	int type, prog_fd, perf_fd;

	if (argc == 3 && !strcmp(argv[1], "--kprobe-multi"))
		return link_kprobe_multi(argv[2]);
	type = uprobe_type();
	if (type < 0) {
		fprintf(stderr, "no uprobe PMU\n");
		return 2;
	}
	n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (n < 0) {
		fprintf(stderr, "readlink: %s\n", strerror(errno));
		return 2;
	}
	self[n] = '\0';
	off = exec_offset(self);
	if (off < 0) {
		fprintf(stderr, "no executable segment in %s\n", self);
		return 2;
	}
	prog_fd = find_prog(argc > 1 ? argv[1] : NULL, &id);
	if (prog_fd < 0) {
		fprintf(stderr, "no loaded kprobe-type program\n");
		return 2;
	}
	memset(&pe, 0, sizeof(pe));
	pe.size = sizeof(pe);
	pe.type = (__u32)type;
	pe.config1 = (__u64)(size_t)self;
	pe.config2 = (__u64)off;
	perf_fd = (int)syscall(__NR_perf_event_open, &pe, -1, 0, -1,
			       PERF_FLAG_FD_CLOEXEC);
	if (perf_fd < 0) {
		fprintf(stderr, "perf_event_open: %s\n", strerror(errno));
		return 2;
	}
	if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) == 0) {
		printf("attached prog_id=%u\n", id);
		return 0;
	}
	printf("errno=%d\n", errno);
	return 0;
}
