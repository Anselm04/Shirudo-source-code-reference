// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * opt_next() of util/options.c on every table of up to two options, each
 * part of a spec one of the few that decide: refused before any argument
 * exactly when a name is missing, not "--" and more, holds '=', a summary
 * is missing, a value-taking flag has no metavar, two options share a
 * name or a short name, or the table is past OPT_MAX. And "--list-opts",
 * "--list-cmds" and "-h" with a help: each a listing, and the run done.
 */

#define OPTIONS_TABLE	1
#include "options-next.c"
