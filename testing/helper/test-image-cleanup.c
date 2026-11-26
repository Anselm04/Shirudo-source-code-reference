// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include "../../util/image_runtime.c"
#include "image-cleanup.h"

static struct dm_verity candidate;
static __u32 busy_calls, remove_calls, sleep_calls;
static int remove_result;
static bool invalid_call;

int __wrap_dm_verity_remove(struct dm_verity *device,
			    bool deferred)
{
	if (device != &candidate || deferred || remove_calls != sleep_calls)
		invalid_call = true;
	remove_calls++;
	return remove_calls <= busy_calls ? -EBUSY : remove_result;
}

int __wrap_nanosleep(const struct timespec *req, struct timespec *rem)
{
	if (req->tv_sec || req->tv_nsec != 10000000 ||
	    remove_calls != sleep_calls + 1)
		invalid_call = true;
	sleep_calls++;
	return 0;
}

int main(int argc, char **argv)
{
	__u32 expected_calls = 1;
	int expected_result = 0;
	int ret;

	if (argc != 2)
		return 2;
	if (!strcmp(argv[1], "immediate")) {
		busy_calls = 0;
	} else if (!strcmp(argv[1], "transient")) {
		busy_calls = 2;
		expected_calls = 3;
	} else if (!strcmp(argv[1], "persistent")) {
		busy_calls = 100;
		expected_calls = 100;
		expected_result = -EBUSY;
	} else if (!strcmp(argv[1], "io")) {
		remove_result = -EIO;
		expected_result = -EIO;
	} else if (!strcmp(argv[1], "permission")) {
		remove_result = -EPERM;
		expected_result = -EPERM;
	} else {
		return 2;
	}
	ret = remove_candidate(&candidate);
	printf("rc=%d removes=%u sleeps=%u invalid=%d\n", ret,
	       remove_calls, sleep_calls, invalid_call);
	return ret != expected_result || remove_calls != expected_calls ||
	       sleep_calls != expected_calls - 1 || invalid_call;
}
