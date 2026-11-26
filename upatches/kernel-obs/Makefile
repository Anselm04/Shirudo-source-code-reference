# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Regenerate the signed watch lists after editing watch.list or
# file-watch.list.

.PHONY: lists watch file-watch

lists: watch file-watch

watch:
	python3 gen_watch.py watch.list watch_generated.h

file-watch:
	python3 gen_file_watch.py file-watch.list file_watch_generated.h
