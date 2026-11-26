# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

ROOT := $(abspath ../..)

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

.PHONY: all clean quote-check

all: quote-check

quote-check:
	+$(Q)$(MAKE) -C $(ROOT) config
	+$(Q)$(MAKE) -C $(ROOT) -f Makefile.shirudo quote-check

clean:
	$(Q)rm -f shirudo-quote-check *.o *.d
