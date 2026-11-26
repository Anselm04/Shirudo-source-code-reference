// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "paths.h"
#include "tpm.h"

static int read_register(__u8 out[TPM_DIGEST_LEN])
{
	struct tpm *tpm = NULL;
	int ret;

	if (tpm_open(&tpm))
		return 1;
	ret = tpm_nv_read(tpm, NV_INDEX, out);
	tpm_close(tpm);
	return ret != 0;
}

static int write_extend(int fd)
{
	__u8 command[18] = { 0x80, 0x01 };
	ssize_t written;
	int saved_errno;

	put_be32(command + 2, (__u32)sizeof(command));
	put_be32(command + 6, TPM_CC_NV_EXTEND);
	put_be32(command + 10, NV_INDEX);
	put_be32(command + 14, NV_INDEX);
	errno = 0;
	written = write(fd, command, sizeof(command));
	saved_errno = errno;
	if (written == -1 && saved_errno == EACCES)
		return 0;
	fprintf(stderr, "inherited NV_Extend: wrote %zd/%zu, errno=%d\n",
		written, sizeof(command), saved_errno);
	return 1;
}

int main(void)
{
	__u8 before[TPM_DIGEST_LEN];
	__u8 after[TPM_DIGEST_LEN];
	int status, fd;
	pid_t pid;

	if (read_register(before))
		return 1;
	fd = open("/dev/tpmrm0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("/dev/tpmrm0");
		return 1;
	}
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return 1;
	}
	if (!pid) {
		int ret = write_extend(fd);

		close(fd);
		_exit(ret);
	}
	close(fd);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status)) {
		fputs("inherited NV_Extend was not refused by the LSM\n", stderr);
		return 1;
	}
	if (read_register(after) || memcmp(before, after, sizeof(before))) {
		fputs("inherited NV_Extend changed the register\n", stderr);
		return 1;
	}
	puts("inherited-TPM: unsigned NV_Extend rejected by LSM; value unchanged");
	return 0;
}
