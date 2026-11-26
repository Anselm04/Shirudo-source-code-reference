/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_IMAGE_CLEANUP_H
#define SHIRUDO_TEST_IMAGE_CLEANUP_H

#include <time.h>

#include "util/dm_verity.h"

int __wrap_dm_verity_remove(struct dm_verity *device,
			    bool deferred);
int __wrap_nanosleep(const struct timespec *req, struct timespec *rem);

#endif /* SHIRUDO_TEST_IMAGE_CLEANUP_H */
