// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the util/seal.c creation helpers on paths a shell test names.
 * Subcommand on argv[1]; prints what the test asserts on.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "io.h"
#include "paths.h"
#include "seal.h"

static int append(const char *path, const char *text)
{
	int fd, ret;

	fd = seal_open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0)
		return fd;
	ret = write_complete(fd, text, strlen(text));
	if (close(fd) && !ret)
		ret = -errno;
	return ret;
}

/* The label an inode carries, or none, without following a link. */
static void show_label(const char *path)
{
	char label[128];
	ssize_t n;

	n = lgetxattr(path, XATTR_SEAL, label, sizeof(label) - 1);
	if (n < 0) {
		printf("label=none\n");
		return;
	}
	label[n] = '\0';
	printf("label=%s\n", label);
}

int main(int argc, char **argv)
{
	int ret;

	if (argc < 3) {
		fprintf(stderr, "usage: %s label|mkdir|open|write|inherit|get "
			"<path> [text]\n", argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "get") == 0) {
		show_label(argv[2]);
		return 0;
	}
	if (strcmp(argv[1], "label") == 0) {
		ret = seal_label(argv[2]);
	} else if (strcmp(argv[1], "mkdir") == 0) {
		ret = seal_mkdir_p(argv[2], 0700);
	} else if (strcmp(argv[1], "open") == 0 && argc == 4) {
		ret = append(argv[2], argv[3]);
	} else if (strcmp(argv[1], "write") == 0 && argc == 4) {
		ret = seal_write_file(argv[2], argv[3], strlen(argv[3]),
				      0600);
	} else if (strcmp(argv[1], "inherit") == 0) {
		ret = seal_inherit_path(argv[2]);
	} else {
		fprintf(stderr, "unknown subcommand\n");
		return 2;
	}
	printf("rc=%d\n", ret);
	return ret ? 1 : 0;
}
