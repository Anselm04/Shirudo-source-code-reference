// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The eventlog as status, attest and init read this boot's records back:
 * the replay of the register, the init record and the lines themselves.
 */

#include <stdlib.h>
#include <string.h>

#include "eventlog.h"
#include "fuzz.h"
#include "malloc.h"

/* A boot ID in the seeds, replaced with the running one. */
static const char seed_boot[] = "00000000-0000-4000-8000-000000000000";
static char boot[64];

static int on_line(const char *line, size_t len, void *ctx)
{
	(*(size_t *)ctx) += len;
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	eventlog_boot_id(boot, sizeof(boot));
	if (strlen(boot) != sizeof(seed_boot) - 1)
		abort();
	setenv("SHIRUDO_EVENTLOG_PENDING_PATH", "/nonexistent/eventlog", 1);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct eventlog_init init;
	size_t seen = 0;
	char path[64];
	__u8 root[32];
	char *log, *p;
	int fd;

	log = xmalloc(size + 1);
	if (!log)
		return 0;
	memcpy(log, data, size);
	log[size] = '\0';
	p = log;
	while ((p = memmem(p, size - (size_t)(p - log), seed_boot,
			   sizeof(seed_boot) - 1))) {
		memcpy(p, boot, sizeof(seed_boot) - 1);
		p += sizeof(seed_boot) - 1;
	}
	fd = fuzz_file((const __u8 *)log, size, path, sizeof(path));
	xfree(log, size + 1);
	if (fd < 0)
		return 0;
	setenv("SHIRUDO_EVENTLOG_PATH", path, 1);
	eventlog_replay(root);
	eventlog_boot_init(&init);
	eventlog_boot_lines(on_line, &seen);
	close(fd);
	return 0;
}
