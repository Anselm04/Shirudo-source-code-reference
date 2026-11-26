/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_KEYRING_SEAL_H
#define SHIRUDO_TEST_KEYRING_SEAL_H

#include <stddef.h>

#include "util/keyring.h"

key_serial_t __wrap_keyring_bpf_add_cert(const __u8 *cert, size_t cert_len);
int __wrap_keyring_bpf_seal(void);

#endif /* SHIRUDO_TEST_KEYRING_SEAL_H */
