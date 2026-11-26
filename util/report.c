// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Per-operation JSON report assembly (upatch load/unload --report).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "report.h"
#include "seal.h"

int report_encode(const struct op_report *r, const char *kernel_release,
		  char **out, size_t *cap)
{
	const char *vlog = r->verifier_log ? r->verifier_log : "";
	size_t size = strlen(vlog) * 6 + 16384;	/* worst-case escape + slack */
	struct json_emit e;
	const char *errname;
	char nv_index[16];
	char *buf;

	if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
		       NV_INDEX) < 0)
		return -E2BIG;
	buf = xmalloc(size);
	if (!buf)
		return -ENOMEM;
	e = (struct json_emit){ .buf = buf, .cap = size };

	errname = r->err ? strerrorname_np(r->err) : NULL;

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "result", r->ok ? "ok" : "failed");
	json_kv_string(&e, "op", r->op ? r->op : "");
	json_kv_string(&e, "phase", r->phase ? r->phase : "done");
	if (r->err)
		json_kv_int(&e, "errno", r->err);
	else
		json_kv_null(&e, "errno");
	if (errname)
		json_kv_string(&e, "errno_name", errname);
	else
		json_kv_null(&e, "errno_name");
	json_kv_string(&e, "category", r->category ? r->category
						: (r->ok ? "ok" : "unknown"));
	json_kv_string(&e, "message", r->message);
	/*
	 * The kernel quotes the program's source lines and the names of
	 * its source files in the log as the compiler took them: a byte
	 * that is no UTF-8 in one must not cost the report of the rejection
	 * the log explains.
	 */
	json_kv_string_lossy(&e, "verifier_log", vlog);
	json_kv_int(&e, "loader_return", r->loader_return);

	json_obj_open_key(&e, "upatch");
	/*
	 * The path is as the caller spelled it and the name as the file has
	 * it, before anything checked either: a byte that is no UTF-8 must
	 * not cost the report of the refusal it is part of.
	 */
	json_kv_string_lossy(&e, "path", r->path ? r->path : "");
	json_kv_string_lossy(&e, "name", r->name ? r->name : "");
	json_kv_string(&e, "payload_sha256", r->payload_hex);
	json_obj_close(&e);

	json_obj_open_key(&e, "kernel");
	json_kv_string_lossy(&e, "release", kernel_release);
	json_obj_close(&e);

	if (r->ok && r->tpm_present) {
		json_obj_open_key(&e, "tpm");
		json_kv_string(&e, "nv_index", nv_index);
		json_kv_string(&e, "chain_after", r->chain_after);
		json_obj_close(&e);
	} else {
		json_kv_null(&e, "tpm");
	}
	json_obj_close(&e);

	if (e.err) {
		xfree(buf, size);
		return e.err;
	}
	*out = buf;
	*cap = size;
	return 0;
}

int report_emit(const char *path, const struct op_report *r)
{
	struct seal_output out;
	struct utsname uts;
	size_t cap;
	char *buf;
	int ret;

	ret = report_encode(r, uname(&uts) ? "" : uts.release, &buf, &cap);
	if (ret) {
		pr_err("report: encode failed: %s", strerror(-ret));
		return ret;
	}
	if (strcmp(path, "-") == 0) {
		printf("%s\n", buf);
		xfree(buf, cap);
		return 0;
	}
	ret = seal_output_create(&out, path, 0644);
	if (ret) {
		pr_err("report: open %s: %s", path, strerror(-ret));
		xfree(buf, cap);
		return ret;
	}
	ret = seal_output_commit(&out, buf, strlen(buf));
	if (ret)
		pr_err("report: write %s: %s", path, strerror(-ret));
	xfree(buf, cap);
	return ret;
}

void report_set_log(struct op_report *r, const char *log)
{
	if (!r)
		return;
	xstrfree(r->verifier_log);
	r->verifier_log = NULL;
	if (!log || !*log)
		return;
	/*
	 * The verifier log is kernel-provided diagnostic output -- bound
	 * the read, copy with xstrndup, and scrub on free via xstrfree.
	 */
	r->verifier_log = xstrndup(log, VERIFIER_LOG_MAX);
}

void report_free(struct op_report *r)
{
	xstrfree(r->verifier_log);
	r->verifier_log = NULL;
}
