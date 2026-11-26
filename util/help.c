// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared structured-help printer for the top-level subcommands.
 */

#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "help.h"
#include "options.h"
#include "similar.h"

#define SUBCMD_MAX	32

/* Wrap target for help-item summaries; covers a 100-col terminal with slack. */
#define HELP_WIDTH	90

static void wrap_print(const char *text, size_t indent, size_t avail)
{
	const char *p = text;
	size_t col = 0;

	if (avail < 1)
		avail = 1;
	while (*p) {
		const char *w;
		size_t wlen;

		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		w = p;
		while (*p && *p != ' ' && *p != '\t')
			p++;
		wlen = (size_t)(p - w);

		if (col == 0) {
			fwrite(w, 1, wlen, stderr);
			col = wlen;
		} else if (col + 1 + wlen <= avail) {
			fputc(' ', stderr);
			fwrite(w, 1, wlen, stderr);
			col += 1 + wlen;
		} else {
			size_t i;

			fputc('\n', stderr);
			for (i = 0; i < indent; i++)
				fputc(' ', stderr);
			fwrite(w, 1, wlen, stderr);
			col = wlen;
		}
	}
	fputc('\n', stderr);
}

int is_help(const char *arg)
{
	return arg && (strcmp(arg, "help") == 0 ||
		       strcmp(arg, "--help") == 0 ||
		       strcmp(arg, "-h") == 0);
}

int is_list_cmds(const char *arg)
{
	return arg && strcmp(arg, "--list-cmds") == 0;
}

void print_subcmd_list(const struct help_item *items,
		       size_t n_items)
{
	size_t i;

	for (i = 0; i < n_items; i++)
		printf("%s\n", items[i].name);
}

/* An option as help shows it: "-o, --output <path>", "--json[=<path>]". */
static const char *option_label(const struct opt_spec *o, char *buf,
				size_t size)
{
	char alias[5] = "";
	int ret;

	if (o->short_name &&
	    strsprintf(alias, sizeof(alias), "-%c, ", o->short_name) < 0)
		return o->name;
	if (!o->metavar)
		ret = strsprintf(buf, size, "%s%s", alias, o->name);
	else if (o->flags & OPT_OPTIONAL)
		ret = strsprintf(buf, size, "%s%s[=%s]", alias, o->name,
				 o->metavar);
	else
		ret = strsprintf(buf, size, "%s%s %s", alias, o->name,
				 o->metavar);
	return ret < 0 ? o->name : buf;
}

static void print_row(const char *name, const char *summary, size_t w)
{
	size_t indent = 2 + w;
	size_t avail = indent < HELP_WIDTH ? HELP_WIDTH - indent : 1;

	fprintf(stderr, "  %-*s", (int)w, name);
	wrap_print(summary, indent, avail);
}

static void print_section(const struct help_section *s)
{
	char label[96];
	size_t i, w = 0;

	if (!s->n_items && !s->n_options)
		return;
	/*
	 * Per section, so an Options section reads as cleanly as a
	 * Subcommands one.
	 */
	for (i = 0; i < s->n_items; i++)
		w = max(w, strlen(s->items[i].name));
	for (i = 0; i < s->n_options; i++)
		w = max(w, strlen(option_label(&s->options[i], label,
					       sizeof(label))));
	w += 2;
	fprintf(stderr, "\n%s\n", s->header);
	for (i = 0; i < s->n_items; i++)
		print_row(s->items[i].name, s->items[i].summary, w);
	for (i = 0; i < s->n_options; i++)
		print_row(option_label(&s->options[i], label, sizeof(label)),
			  s->options[i].summary, w);
}

void print_help(const struct help *h)
{
	size_t i;

	if (h->usage)
		fprintf(stderr, "usage: %s\n", h->usage);
	if (h->summary && *h->summary)
		fprintf(stderr, "\n%s\n", h->summary);
	for (i = 0; i < h->n_sections; i++)
		print_section(&h->sections[i]);
	if (h->footer && *h->footer)
		fprintf(stderr, "\n%s\n", h->footer);
}

void help_suggest(const char *bad, const char *const *names, size_t n_names)
{
	struct suggestion sugg[4];
	size_t i, n;
	int max_dist;

	/*
	 * A quarter of the length is too tight for short words and lets
	 * anything through for long ones, so half plus one, at most 3.
	 */
	max_dist = min((int)strlen(bad) / 2 + 1, 3);
	n = suggest(bad, names, n_names, max_dist, sugg, ARRAY_SIZE(sugg));
	if (!n)
		return;
	fprintf(stderr, "\nDid you mean one of:\n");
	for (i = 0; i < n; i++)
		fprintf(stderr, "\t%s\n", sugg[i].name);
}

static void
help_unknown_subcommand(const char *cmd_label, const char *bad,
			const struct help_item *subcmds,
			size_t n_subcmds)
{
	const char *names[SUBCMD_MAX];
	size_t i, n_names = 0;

	fprintf(stderr, "%s: '%s' is not a known subcommand.\n"
		"See '%s --help'.\n", cmd_label, bad, cmd_label);
	for (i = 0; subcmds && i < n_subcmds && n_names < SUBCMD_MAX; i++)
		names[n_names++] = subcmds[i].name;
	help_suggest(bad, names, n_names);
}

const char *resolve_subcommand(const char *cmd_label,
			       const char *input,
			       const struct help_item *subcmds,
			       size_t n_subcmds)
{
	const char *names[SUBCMD_MAX];
	size_t matches[SUBCMD_MAX];
	size_t i, n_names = 0, n;

	if (!subcmds || !n_subcmds) {
		help_unknown_subcommand(cmd_label, input,
					subcmds, n_subcmds);
		return NULL;
	}
	for (i = 0; i < n_subcmds && n_names < ARRAY_SIZE(names); i++)
		names[n_names++] = subcmds[i].name;

	n = resolve(input, names, n_names, matches,
		    ARRAY_SIZE(matches));
	if (n == 1)
		return names[matches[0]];
	if (n == 0) {
		help_unknown_subcommand(cmd_label, input,
					subcmds, n_subcmds);
		return NULL;
	}
	fprintf(stderr, "%s: '%s' is ambiguous; matches:\n", cmd_label, input);
	for (i = 0; i < n; i++)
		fprintf(stderr, "\t%s\n", names[matches[i]]);
	return NULL;
}
