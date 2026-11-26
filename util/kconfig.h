/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A line of a kernel configuration, as /proc/config.gz and
 * /boot/config-<release> hold them.
 */

#ifndef SHIRUDO_KCONFIG_H
#define SHIRUDO_KCONFIG_H

#include <stdbool.h>

/* The most bytes of a line that sets an option; a longer one sets none. */
#define KCONFIG_LINE_MAX	8191u

/*
 * Whether line sets an option, and then its name in *key and its value
 * in *value: "CONFIG_X=<value>" gives the value, without the double
 * quotes around a string, and "# CONFIG_X is not set" gives "n". White
 * space around the line, the name and the value is no part of them. Any
 * other comment, a name that is not CONFIG_ and more, and text behind
 * "is not set" set no option. line is cut up for the two, which point
 * into it.
 */
bool kconfig_line(char *line, const char **key, const char **value);

#endif /* SHIRUDO_KCONFIG_H */
