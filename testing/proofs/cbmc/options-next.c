// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * opt_next() of util/options.c from every state a run of calls reaches,
 * on every command line of up to ARGS_MAX arguments of up to LEN bytes,
 * against a table with an option of each kind: each call takes at least
 * one argument, so a run ends, what it hands back lies in an argument, a
 * flag has no value, a value is there and not empty unless the option
 * allows it, and no option comes back twice unless it repeats.
 * options-table.c includes this file for the table and the listings,
 * options-long.c for an unknown option too long to suggest one for.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/options.c"

#define ARGS_MAX	3

enum { P_A, P_BB, P_C, P_D, P_N, P_COUNT };

static const struct opt_spec specs[] = {
	[P_A]  = { "--a", 'a', 0, "<v>", "a value" },
	[P_BB] = { "--bb", 0, 0, NULL, "a flag" },
	[P_C]  = { "--c", 0, OPT_OPTIONAL, "<v>", "a value after = or none" },
	[P_D]  = { "--d", 0, OPT_REPEAT | OPT_EMPTY, "<v>", "repeats, may be empty" },
	[P_N]  = { "--n", 0, 0, "<n>", "a number" },
};

void pr_err(const char *fmt, ...)
{
}

/* The messages are not read here; the format proofs cover the text. */
int vstrsprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	if (size)
		buf[0] = '\0';
	return 0;
}

/* The contract string-number proves: a number up to max, or an error. */
int parse_u64(const char *s, size_t len, __u64 max, __u64 *out)
{
	__u64 v;
	int ret;

	__CPROVER_assert(__CPROVER_r_ok(s, len), "the digits are readable");
	if (ret)
		return ret < 0 ? ret : -EINVAL;
	__CPROVER_assume(v <= max);
	*out = v;
	return 0;
}

void print_help(const struct help *h)
{
}

/* As util/help.c has it. */
int is_list_cmds(const char *arg)
{
	return arg && strcmp(arg, "--list-cmds") == 0;
}

void help_suggest(const char *bad, const char *const *names, size_t n_names)
{
	__CPROVER_assert(n_names <= OPT_MAX, "the names fit");
	__CPROVER_assert(strlen(bad) <= SIMILAR_MAX_LEN, "the word fits");
}

#if defined(OPTIONS_TABLE)
/* A table of up to two options, each part one of a few that matter. */
static const char *const names[] = {
	"--a", "--b", "--a=", "--", "-a", NULL,
};

static void any_spec(struct opt_spec *s)
{
	size_t name;
	bool shorted, metavar, summary;
	__u32 flags;

	__CPROVER_assume(name < ARRAY_SIZE(names));
	*s = (struct opt_spec){
		names[name], shorted ? 'a' : 0, flags & 7,
		metavar ? "<v>" : NULL, summary ? "s" : NULL,
	};
}

static bool spec_ok(const struct opt_spec *s)
{
	return s->name && s->name[0] == '-' && s->name[1] == '-' &&
	       s->name[2] && !strchr(s->name, '=') && s->summary &&
	       (s->metavar || !(s->flags & (OPT_EMPTY | OPT_OPTIONAL)));
}

static bool specs_apart(const struct opt_spec *a, const struct opt_spec *b)
{
	return strcmp(a->name, b->name) &&
	       (!a->short_name || a->short_name != b->short_name);
}

/* Any table: OPT_USAGE before any argument exactly when malformed. */
static void any_table(void)
{
	static const char *const none[1];
	struct opt_spec table[2];
	struct opt_parser p;
	size_t n;
	bool ok;
	int opt;

	any_spec(&table[0]);
	any_spec(&table[1]);
	__CPROVER_assume(n <= 2 || n == OPT_MAX + 1);
	ok = n <= OPT_MAX && (n < 1 || spec_ok(&table[0])) &&
	     (n < 2 || (spec_ok(&table[1]) &&
			specs_apart(&table[1], &table[0])));
	OPT_INIT(&p, "proof", table, NULL, 0, none, 0);
	p.n_specs = n;
	opt = opt_next(&p);
	__CPROVER_assert(opt == (ok ? OPT_END : OPT_USAGE),
			 "a malformed table refused, a sound one read");
}

/* "--list-opts", "--list-cmds" and "-h" with a help: done, nothing else. */
static void listings(void)
{
	static const char *const asked[] = { "--list-opts", "--list-cmds", "-h" };
	static const struct help help = {};
	struct opt_parser p;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(asked); i++) {
		OPT_INIT(&p, "proof", specs, &help, 1, &asked[i], 0);
		__CPROVER_assert(opt_next(&p) == OPT_DONE && p.next == 1,
				 "a listing asked for, and the run done");
	}
}

void harness(void)
{
	any_table();
	listings();
}
#elif defined(OPTIONS_LONG)
/* One unknown option of LEN bytes, "--" and then a constant byte. */
void harness(void)
{
	char text[LEN + 1];
	const char *arg = text;
	struct opt_parser p;

	memcpy(text, "--", 2);
	memset(text + 2, 'x', LEN - 2);
	text[LEN] = '\0';
	OPT_INIT(&p, "proof", specs, NULL, 1, &arg, 0);
	__CPROVER_assert(opt_next(&p) == OPT_USAGE, "an unknown option refused");
}
#else
static const char *argv[ARGS_MAX];
static size_t lens[ARGS_MAX];

static const char *any_string(size_t *len)
{
	char *s;

	__CPROVER_assume(*len <= LEN);
	s = any_bytes(*len + 1);
	__CPROVER_assume(!s[*len] && strnlen(s, *len) == *len);
	return s;
}

static bool in_args(const char *v, int argc)
{
	int k;

	for (k = 0; k < argc; k++)
		if (__CPROVER_same_object(v, argv[k]) &&
		    __CPROVER_POINTER_OFFSET(v) <= lens[k])
			return true;
	return false;
}

void harness(void)
{
	bool checked, args_only;
	const struct opt_spec *s;
	int argc, i, next, opt;
	__u64 given_before, n;
	struct opt_parser p;

	__CPROVER_assume(argc >= 0 && argc <= ARGS_MAX);
	for (i = 0; i < argc; i++) {
		size_t len;

		argv[i] = any_string(&len);
		lens[i] = len;
	}
	OPT_INIT(&p, "proof", specs, NULL, argc, argv, 0);
	/* Any state a run of calls reaches: the next argument, what came. */
	__CPROVER_assume(next >= 0 && next <= argc);
	__CPROVER_assume(!(given_before >> P_COUNT));
	p.next = next;
	p.given = given_before;
	p.checked = checked;
	p.args_only = args_only;

	opt = opt_next(&p);
	__CPROVER_assert(p.next <= argc, "never past the arguments");
	if (opt == OPT_END) {
		__CPROVER_assert(p.next == argc,
				 "the end only where no argument is left");
		return;
	}
	if (opt == OPT_DONE || opt == OPT_USAGE)
		return;
	__CPROVER_assert(p.next > next, "every call takes an argument");
	if (opt == OPT_ARG) {
		__CPROVER_assert(p.value == argv[p.next - 1],
				 "an argument is the one it took");
		return;
	}
	__CPROVER_assert(opt >= 0 && opt < P_COUNT, "an option of the table");
	__CPROVER_assert(opt_given(&p, opt), "what comes back is marked given");
	s = &specs[opt];
	if (!s->metavar)
		__CPROVER_assert(!p.value, "a flag has no value");
	else if (p.value)
		__CPROVER_assert(in_args(p.value, argc) &&
				 (*p.value || (s->flags & OPT_EMPTY)),
				 "a value in an argument, empty only where allowed");
	else
		__CPROVER_assert(s->flags & OPT_OPTIONAL,
				 "only an optional value may be left out");
	__CPROVER_assert(!(given_before & (1ULL << opt)) ||
			 (s->flags & OPT_REPEAT),
			 "an option comes once unless it repeats");
	if (opt == P_N && !opt_u64(&p, 1, 512, &n))
		__CPROVER_assert(n >= 1 && n <= 512, "a number in bounds");
}
#endif
