# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

ROOT := $(abspath ../..)

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

.PHONY: all clean shirudo-build

all: shirudo-build

shirudo-build:
	+$(Q)$(MAKE) -C $(ROOT) config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo shirudo-build

clean:
	$(Q)rm -f shirudo-build *.o *.d
