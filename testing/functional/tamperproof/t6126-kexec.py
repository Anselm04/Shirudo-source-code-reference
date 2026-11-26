#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# One kexec load by each system call, nothing executed: kexec_load with
# no segments, which unloads, and kexec_file_load of the given image
# followed by its unload. Prints the errno of each, 0 for success.

import ctypes
import os
import platform
import sys

NR = {
    "x86_64": (246, 320),
    "aarch64": (104, 294),
    "riscv64": (104, 294),
}
KEXEC_FILE_UNLOAD = 0x1
KEXEC_FILE_NO_INITRAMFS = 0x4

libc = ctypes.CDLL(None, use_errno=True)
nr_load, nr_file_load = NR[platform.machine()]

ret = libc.syscall(nr_load, ctypes.c_ulong(0), ctypes.c_ulong(0), None,
                   ctypes.c_ulong(0))
load_errno = ctypes.get_errno() if ret < 0 else 0

fd = os.open(sys.argv[1], os.O_RDONLY)
ret = libc.syscall(nr_file_load, fd, -1, ctypes.c_ulong(1), b"\0",
                   ctypes.c_ulong(KEXEC_FILE_NO_INITRAMFS))
file_errno = ctypes.get_errno() if ret < 0 else 0
if ret == 0:
    libc.syscall(nr_file_load, -1, -1, ctypes.c_ulong(0), None,
                 ctypes.c_ulong(KEXEC_FILE_UNLOAD))
os.close(fd)
print(load_errno, file_errno)
