# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the vendored libbpf as a static archive. The sources under bpf/
# and include/uapi/ are copied verbatim from a kernel tree by
# tools/bpf-deps/bpf-deps.sh; include/linux and include/asm are small
# shirudo-owned shims standing in for the kernel's tools/include.

CC ?= cc
AR ?= ar
Q  ?= @
EXTRA_CFLAGS ?=

LIBBPF_CFLAGS := -O2 -g -std=gnu89 -fvisibility=hidden -fPIC \
                 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 \
                 -Wall -Wno-switch-enum -Wno-unused-parameter \
                 -Iinclude -Iinclude/uapi -Ibpf $(EXTRA_CFLAGS)

SRCS := $(wildcard bpf/*.c)
OBJS := $(SRCS:.c=.o)

all: libbpf.a

libbpf.a: $(OBJS)
	@printf '  AR      vendor/libbpf/$@\n'
	$(Q)rm -f $@
	$(Q)$(AR) rcs $@ $^

bpf/%.o: bpf/%.c
	@printf '  CC      vendor/libbpf/$@\n'
	$(Q)$(CC) $(LIBBPF_CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJS:.o=.d)

clean:
	$(Q)rm -f libbpf.a bpf/*.o bpf/*.d

.PHONY: all clean
