// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_selector_matches() of util/bpm_tree_state.c returns 1 exactly where
 * selectorMatches of testing/proofs/lean4/Shirudo/TreeOverlap.lean holds,
 * for release prefixes, build IDs, architectures and labels. The node is a
 * stub; a selector that names a kernel option is not covered here.
 */

/* util/string.c behind a file that includes its header. */
#define STRING_INTERNAL

/* CBMC's own memcpy() of a length it does not know runs out of memory. */
#define PROOF_MEMCPY_BYTEWISE

/*
 * tree_selector_matches() keeps the node's labels in a table of
 * TREE_MAX_LABELS entries of 512 bytes and reads a value through the
 * pointer kv_value() returns, which CBMC lets be any byte of the table:
 * 64 entries take 11 GB. The labels here never fill four, as LABELS_FIT
 * checks, so a table of four takes the paths one of 64 does.
 */
#define TREE_MAX_LABELS	4

/* For an errno that keeps what a stub stored. */
#define PROOF_FILE	1

/*
 * struct utsname with a first member that is no array of char: CBMC 5.95
 * reads wrong bytes at an offset that depends on the data, as
 * release[strlen(prefix)] is, from an object whose type starts with one.
 */
#define _SYS_UTSNAME_H	1
struct utsname {
	long	first;
	char	sysname[65];
	char	nodename[65];
	char	release[65];
	char	version[65];
	char	machine[65];
	char	domainname[65];
};

#include "proof.h"

#define LIST_MAX	2
#define TEXT_MAX	2
#define OPTIONS_MAX	2

/* The node: what uname() and the kernel's notes give, or their failure. */
static char node_release[TEXT_MAX + 1], node_machine[TEXT_MAX + 1];
static char node_build_id[TEXT_MAX + 1];
static bool uname_fails, build_id_fails;

int uname(struct utsname *u)
{
	if (uname_fails)
		return -1;
	for (int i = 0; i <= TEXT_MAX; i++) {
		u->release[i] = node_release[i];
		u->machine[i] = node_machine[i];
	}
	return 0;
}

#include "../../../util/bpm_tree_state.c"
#include "../../../util/kernel_release.c"
#include "../../../util/string.c"
#include "bpm-tree-overlap-model.h"

int kernel_build_id_read(char out[KERNEL_BUILD_ID_STRING_MAX])
{
	if (build_id_fails)
		return -ENOENT;
	for (int i = 0; i <= TEXT_MAX; i++)
		out[i] = node_build_id[i];
	return 0;
}

/* No selector here names a kernel option. */
static const char *model_kconfig(const char *key)
{
	return NULL;
}

/*
 * LEN picks what the selector names: 0 release prefixes, build IDs and
 * architectures, 1 to 3 labels, read from /etc (1), from an empty config
 * image (2) or from a file whose first line fails (3). These are constants:
 * CBMC follows the bytes of a line only when no branch wrote them.
 */
#define IMAGE_ACTIVE	(LEN == 2)
#define LINE_FAILS	(LEN == 3)
#define LABEL_LINES	(IMAGE_ACTIVE ? 0 : 5)
#define LABELS		(IMAGE_ACTIVE ? 0 : 3)
_Static_assert(LABELS <= TREE_MAX_LABELS, "LABELS_FIT: the labels fit");

static const char *const label_lines[] = {
	"a=x\n", "# c=1\n", " b = y\x20\n", "junk\n", "a=z\n",
};

/* A blank before the '=' stays in the key, as the format says. */
static const struct tree_kv node_labels[] = {
	{ "a", "x" }, { "b ", "y" }, { "a", "z" },
};

static int open_error, stream_error;
static int n_lines, n_opened, n_closed, n_fd_closed, n_line_freed;
static char label_line[16];
static FILE label_stream;

bool image_config_active(void)
{
	return IMAGE_ACTIVE;
}

int image_open(enum image_path which, int flags)
{
	__CPROVER_assert(IMAGE_ACTIVE && which == IMAGE_NODE_LABELS,
			 "the labels of the active config image");
	return open_error ? open_error : 3;
}

FILE *fdopen(int fd, const char *mode)
{
	__CPROVER_assert(fd == 3, "the descriptor image_open() gave");
	if (stream_error) {
		errno = -stream_error;
		return NULL;
	}
	n_opened++;
	return &label_stream;
}

FILE *fopen(const char *path, const char *mode)
{
	static const char labels[] = "/etc/shirudo/node.labels";

	__CPROVER_assert(!IMAGE_ACTIVE &&
			 !memcmp(path, labels, sizeof(labels)),
			 "the labels of /etc without a config image");
	if (open_error) {
		errno = -open_error;
		return NULL;
	}
	n_opened++;
	return &label_stream;
}

int fclose(FILE *f)
{
	__CPROVER_assert(f == &label_stream, "the stream that was opened");
	n_closed++;
	return 0;
}

int close(int fd)
{
	__CPROVER_assert(fd == 3, "the descriptor image_open() gave");
	n_fd_closed++;
	return 0;
}

int read_text_line(FILE *f, char **line, size_t *cap, size_t max)
{
	const char *text;
	int i;

	if (LINE_FAILS)
		return -EIO;
	if (n_lines == LABEL_LINES)
		return 0;
	text = label_lines[n_lines++];
	for (i = 0; text[i]; i++)
		label_line[i] = text[i];
	label_line[i] = '\0';
	*line = label_line;
	*cap = sizeof(label_line);
	return 1;
}

void libc_free(void *p)
{
	__CPROVER_assert(!p || p == label_line, "the line that was read");
	n_line_freed++;
}

/* The selector lies in an operation, as bpm-tree-overlap-model.c has it. */
static void short_text(const char *s)
{
	__CPROVER_assume(!s[TEXT_MAX]);
}

static void short_list(const char (*list)[TREE_STRING_MAX], int n, int max)
{
	__CPROVER_assume(n >= 0 && n <= max);
	for (int i = 0; i < max; i++)
		short_text(list[i]);
}

static void short_pairs(const struct tree_selector_kv *kvs, int n, int max)
{
	__CPROVER_assume(n >= 0 && n <= max);
	for (int i = 0; i < max; i++) {
		short_text(kvs[i].key);
		short_list(kvs[i].values, kvs[i].n_values, LIST_MAX);
	}
}

/* 0 or a negative errno, as the kernel numbers them. */
static bool no_errno(int ret)
{
	return ret <= 0 && ret >= -4095;
}

static void any_text(char *s)
{
	char any[TEXT_MAX];

	for (int i = 0; i < TEXT_MAX; i++)
		s[i] = any[i];
}

#ifdef TREE_STATE_OPTIONS
/*
 * tree_map_pair() keeps a kconfig below TREE_MAX_KCONFIG pairs, half the
 * table: here up to OPTIONS_MAX, of any keys, a key twice among them. The
 * pairs lie in bytes: selector_hash_find() reads the pair at the index
 * the table holds, and CBMC 5.95 reads wrong bytes at such an offset
 * from an array of pairs.
 */
void harness(void)
{
	char kconfig[OPTIONS_MAX * sizeof(struct tree_selector_kv)];
	const struct tree_selector_kv *pairs = (void *)kconfig;
	int slots[TREE_SELECTOR_HASH_SIZE], first = -1;
	char *key = any_bytes(TEXT_MAX + 1);
	struct tree_operation op;
	struct tree_selector *s = &op.selector;

	s->kconfig = (struct tree_selector_kv *)kconfig;
	__CPROVER_assume(s->n_kconfig >= 0 && s->n_kconfig <= OPTIONS_MAX);
	short_text(key);
	for (int i = 0; i < OPTIONS_MAX; i++)
		short_text(pairs[i].key);
	selector_hash_build(s, slots);
	for (int i = OPTIONS_MAX - 1; i >= 0; i--)
		if (i < s->n_kconfig && model_same(pairs[i].key, key))
			first = i;
	__CPROVER_assert(selector_hash_find(s, slots, key) == first,
			 "a key found at its first pair, or not at all");
}
#else
void harness(void)
{
	struct tree_selector_kv labels[LIST_MAX];
	int any_error[2], any_count[3], config_rc, ret;
	struct tree_selector *s;
	struct tree_operation op;
	struct model_node node;
	bool any_flag[2], want;

	/* A global starts as zeros to CBMC, a local as anything. */
	uname_fails = any_flag[0];
	build_id_fails = any_flag[1];
	any_text(node_release);
	any_text(node_machine);
	any_text(node_build_id);
	node = (struct model_node){
		!uname_fails, node_release, node_machine,
		build_id_fails ? NULL : node_build_id, node_labels, LABELS,
	};
	__CPROVER_assert(!tree_selector_matches(NULL), "no selector, no match");

	s = &op.selector;
	s->kconfig = NULL;
	s->labels = labels;
	s->n_kernel_release_prefix = 0;
	s->n_kernel_build_id = 0;
	s->n_architecture = 0;
	s->n_kconfig = 0;
	s->n_labels = 0;
	if (LEN == 0) {
		s->n_kernel_release_prefix = any_count[0];
		s->n_kernel_build_id = any_count[1];
		s->n_architecture = any_count[2];
		short_list(s->kernel_release_prefix,
			   s->n_kernel_release_prefix, LIST_MAX);
		short_list(s->kernel_build_id, s->n_kernel_build_id, LIST_MAX);
		short_list(s->architecture, s->n_architecture, LIST_MAX);
	} else {
		open_error = any_error[0];
		stream_error = any_error[1];
		__CPROVER_assume(no_errno(open_error) &&
				 no_errno(stream_error));
		s->n_labels = any_count[0];
		short_pairs(labels, s->n_labels, LIST_MAX);
	}

	ret = tree_selector_matches(s);
	want = model_selector_matches(&node, s);
	if (LEN == 0) {
		__CPROVER_assert(ret == want, "selectorMatches of the model");
		return;
	}
	if (model_wildcard(s) || uname_fails) {
		__CPROVER_assert(ret == want && !n_opened,
				 "decided before the node's labels are read");
		return;
	}
	__CPROVER_assert(n_closed == n_opened && n_line_freed == n_opened &&
			 n_fd_closed == (IMAGE_ACTIVE && !open_error &&
					 stream_error),
			 "the labels closed, and their line released");
	config_rc = open_error ? open_error :
		    IMAGE_ACTIVE && stream_error ? stream_error :
		    LINE_FAILS ? -EIO : 0;
	if (config_rc)
		__CPROVER_assert(ret == (config_rc == -ENOENT ? 0 : config_rc),
				 "no labels, no match; unreadable, the error");
	else
		__CPROVER_assert(ret == want, "selectorMatches of the model");
}
#endif
