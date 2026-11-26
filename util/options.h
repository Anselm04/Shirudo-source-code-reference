/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The options of every command, from a table indexed by the command's
 * own enum of them, and the rules all of them follow.
 */

#ifndef SHIRUDO_OPTIONS_H
#define SHIRUDO_OPTIONS_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/compiler.h>
#include <shirudo/misc.h>
#include <shirudo/types.h>

/* The exit status of every usage error. */
#define EXIT_USAGE	2

/* The most options one command has: a bit each in opt_parser.given. */
#define OPT_MAX		64

#define OPT_REPEAT	(1u << 0)	/* may be given more than once */
#define OPT_EMPTY	(1u << 1)	/* may be given an empty value */
#define OPT_OPTIONAL	(1u << 2)	/* takes a value after = alone, or none */

/*
 * One option. Where metavar names a value, the option takes one as the
 * next argument or after =; where metavar is NULL, it is a flag.
 */
struct opt_spec {
	const char	*name;		/* "--cert" */
	char		short_name;	/* 'o' for -o, or 0 */
	__u32		flags;
	const char	*metavar;	/* "<path>" */
	const char	*summary;
};

/* What opt_next() returns besides the index of an option. */
#define OPT_END		(-1)	/* no argument is left */
#define OPT_ARG		(-2)	/* an argument, in value */
#define OPT_DONE	(-3)	/* help or the option list printed: exit 0 */
#define OPT_USAGE	(-4)	/* a usage error, already reported */

struct help;

struct opt_parser {
	const char		*command;	/* "attest verify" */
	const struct opt_spec	*specs;
	size_t			n_specs;
	const struct help	*help;
	const char *const	*argv;
	int			argc;
	int			next;
	bool			checked;
	bool			args_only;	/* after "--" */
	__u64			given;
	int			opt;		/* the option last returned */
	const char		*value;
};

/*
 * A parser of argv from first on, against the n_specs options of specs,
 * whose index is the command's enum of them. Its errors start with
 * command, and -h or --help prints help.
 */
void opt_init(struct opt_parser *p, const char *command,
	      const struct opt_spec *specs, size_t n_specs,
	      const struct help *help, int argc, const char *const *argv,
	      int first);

#define OPT_INIT(p, command, specs, help, argc, argv, first)		\
	opt_init(p, command, specs, ARRAY_SIZE(specs), help, argc, argv, first)

/*
 * The index of the next option, with value set where it takes one, NULL
 * for an OPT_OPTIONAL one given without; otherwise one of the OPT_ codes
 * above. An unknown option, a value missing, empty or given to a flag,
 * and an option given twice are usage errors. --list-opts prints the
 * options, one a line, a value's metavar after a tab, for completion,
 * and --list-cmds the subcommands, which are none.
 */
int opt_next(struct opt_parser *p);

/* Whether the option of index opt was given. */
static inline bool opt_given(const struct opt_parser *p, int opt)
{
	return p->given & (1ULL << opt);
}

/*
 * The value of the option last returned as a number from min to max: 0,
 * or OPT_USAGE, reported.
 */
int opt_u64(const struct opt_parser *p, __u64 min, __u64 max,
	    __u64 *out) __must_check;

/* A name an option's value may be, and the value it stands for. */
struct opt_name {
	const char	*name;
	int		value;
};

/*
 * The value of the name the option last returned was given, from the n
 * names of names: 0, or OPT_USAGE, reported with the names it takes.
 */
int opt_choice(const struct opt_parser *p, const struct opt_name *names,
	       size_t n, int *out) __must_check;

#define OPT_CHOICE(p, names, out)					\
	opt_choice(p, names, ARRAY_SIZE(names), out)

/*
 * Reports a usage error the command finds, as "<command>: <message>";
 * the caller returns OPT_USAGE or EXIT_USAGE.
 */
void opt_usage(const struct opt_parser *p, const char *fmt, ...)
	__printf(2, 3);

#endif /* SHIRUDO_OPTIONS_H */
