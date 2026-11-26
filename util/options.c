// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The one parser of command line options, and the rules it holds every
 * command to.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "help.h"
#include "log.h"
#include "options.h"
#include "similar.h"

void opt_usage(const struct opt_parser *p, const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vstrsprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	pr_err("%s: %s", p->command, ret < 0 ? fmt : msg);
}

void opt_init(struct opt_parser *p, const char *command,
	      const struct opt_spec *specs, size_t n_specs,
	      const struct help *help, int argc, const char *const *argv,
	      int first)
{
	*p = (struct opt_parser) {
		.command	= command,
		.specs		= specs,
		.n_specs	= n_specs,
		.help		= help,
		.argv		= argv,
		.argc		= argc,
		.next		= first,
		.opt		= OPT_END,
	};
}

/*
 * A table with a hole, a name twice, or a flag marked as taking a value
 * would leave an option unreachable or read wrong, whatever the command
 * line; refuse it before any argument is read.
 */
static bool specs_valid(const struct opt_spec *specs, size_t n)
{
	size_t i, j;

	if (n > OPT_MAX)
		return false;
	for (i = 0; i < n; i++) {
		const struct opt_spec *s = &specs[i];

		if (!s->name || !str_has_prefix(s->name, "--") ||
		    !s->name[2] || strchr(s->name, '=') || !s->summary)
			return false;
		if (!s->metavar && (s->flags & (OPT_EMPTY | OPT_OPTIONAL)))
			return false;
		for (j = 0; j < i; j++) {
			if (!strcmp(s->name, specs[j].name) ||
			    (s->short_name &&
			     s->short_name == specs[j].short_name))
				return false;
		}
	}
	return true;
}

/*
 * The index of the option arg names, -1 for none, and in *eq what follows
 * its = where it has one. A short option stands alone: -o, never -ovalue
 * or -fo.
 */
static int spec_find(const struct opt_parser *p, const char *arg,
		     const char **eq)
{
	size_t i, len;

	*eq = NULL;
	if (arg[1] != '-') {
		if (arg[2])
			return -1;
		for (i = 0; i < p->n_specs; i++)
			if (p->specs[i].short_name == arg[1])
				return (int)i;
		return -1;
	}
	len = span_until(arg, strlen(arg), "=");
	if (arg[len])
		*eq = arg + len + 1;
	for (i = 0; i < p->n_specs; i++) {
		const char *name = p->specs[i].name;

		if (span_equals_str(arg, len, name))
			return (int)i;
	}
	return -1;
}

static int opt_unknown(const struct opt_parser *p, const char *arg)
{
	size_t i, len = strlen(arg);
	const char *names[OPT_MAX];
	char bad[SIMILAR_MAX_LEN + 1];

	if (arg[1] == '-')
		len = span_until(arg, len, "=");
	pr_err("%s: unknown option '%.*s'", p->command, (int)len, arg);
	if (len >= sizeof(bad))
		return OPT_USAGE;
	memcpy(bad, arg, len);
	bad[len] = '\0';
	for (i = 0; i < p->n_specs; i++)
		names[i] = p->specs[i].name;
	help_suggest(bad, names, p->n_specs);
	return OPT_USAGE;
}

/* What bash completion reads: "--json=\t<path>", "--cert\t<path>", "-o". */
static int opt_list(const struct opt_parser *p)
{
	size_t i;

	for (i = 0; i < p->n_specs; i++) {
		const struct opt_spec *s = &p->specs[i];
		const char *eq = s->flags & OPT_OPTIONAL ? "=" : "";

		if (s->short_name)
			printf("-%c%s%s\n", s->short_name,
			       s->metavar ? "\t" : "",
			       s->metavar ? s->metavar : "");
		if (s->metavar)
			printf("%s%s\t%s\n", s->name, eq, s->metavar);
		else
			printf("%s\n", s->name);
	}
	return OPT_DONE;
}

static int opt_take_value(struct opt_parser *p, const struct opt_spec *s,
			  const char *eq)
{
	if (!s->metavar) {
		if (!eq)
			return 0;
		opt_usage(p, "%s takes no value", s->name);
		return OPT_USAGE;
	}
	if (eq) {
		p->value = eq;
	} else if (s->flags & OPT_OPTIONAL) {
		return 0;
	} else if (p->next < p->argc) {
		p->value = p->argv[p->next++];
	} else {
		opt_usage(p, "%s takes a value", s->name);
		return OPT_USAGE;
	}
	if (!*p->value && !(s->flags & OPT_EMPTY)) {
		opt_usage(p, "%s takes a value, not an empty one", s->name);
		return OPT_USAGE;
	}
	return 0;
}

int opt_next(struct opt_parser *p)
{
	const struct opt_spec *s;
	const char *arg, *eq;
	int opt;

	if (!p->checked && !specs_valid(p->specs, p->n_specs)) {
		opt_usage(p, "the table of its options is malformed");
		return OPT_USAGE;
	}
	p->checked = true;
	p->value = NULL;
	p->opt = OPT_END;
	for (;;) {
		if (p->next >= p->argc)
			return OPT_END;
		arg = p->argv[p->next++];
		if (p->args_only || arg[0] != '-' || !arg[1]) {
			p->value = arg;
			return OPT_ARG;
		}
		if (strcmp(arg, "--"))
			break;
		p->args_only = true;
	}
	if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
		if (p->help)
			print_help(p->help);
		return OPT_DONE;
	}
	if (!strcmp(arg, "--list-opts"))
		return opt_list(p);
	/* A command whose options this parser reads has no subcommands. */
	if (is_list_cmds(arg))
		return OPT_DONE;
	opt = spec_find(p, arg, &eq);
	if (opt < 0)
		return opt_unknown(p, arg);
	s = &p->specs[opt];
	if (opt_given(p, opt) && !(s->flags & OPT_REPEAT)) {
		opt_usage(p, "%s given twice", s->name);
		return OPT_USAGE;
	}
	if (opt_take_value(p, s, eq))
		return OPT_USAGE;
	p->given |= 1ULL << opt;
	p->opt = opt;
	return opt;
}

int opt_u64(const struct opt_parser *p, __u64 min, __u64 max, __u64 *out)
{
	__u64 v;

	if (p->opt < 0 || !p->value) {
		opt_usage(p, "no option value to read as a number");
		return OPT_USAGE;
	}
	if (parse_u64(p->value, strlen(p->value), max, &v) || v < min) {
		opt_usage(p, "%s takes a number from %llu to %llu",
			  p->specs[p->opt].name, min, max);
		return OPT_USAGE;
	}
	*out = v;
	return 0;
}

int opt_choice(const struct opt_parser *p, const struct opt_name *names,
	       size_t n, int *out)
{
	char list[256] = "";
	size_t i, len = 0;

	if (p->opt < 0 || !p->value) {
		opt_usage(p, "no option value to read as a name");
		return OPT_USAGE;
	}
	for (i = 0; i < n; i++) {
		if (!strcmp(p->value, names[i].name)) {
			*out = names[i].value;
			return 0;
		}
	}
	for (i = 0; i < n; i++) {
		const char *sep = !i ? "" : i + 1 < n ? ", " : " or ";
		int ret = strsprintf(list + len, sizeof(list) - len, "%s%s",
				     sep, names[i].name);

		if (ret < 0)
			break;
		len += (size_t)ret;
	}
	opt_usage(p, "%s takes %s", p->specs[p->opt].name, list);
	return OPT_USAGE;
}
