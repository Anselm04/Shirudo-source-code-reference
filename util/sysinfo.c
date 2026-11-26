// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Host system overview from /proc, /etc and uname(2). No subprocess.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "kconfig.h"
#include "kernel_build_id.h"
#include "malloc.h"
#include "sysinfo.h"

static void read_first_line(const char *path, char *buf, size_t cap)
{
	ssize_t n;
	int fd;

	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n <= 0 ||
	    span_to_str(buf, cap, buf, span_until(buf, (size_t)n, "\r\n")))
		buf[0] = '\0';
}

#define OS_RELEASE_SIZE_MAX	(64u * 1024u)
/* Above the COMMAND_LINE_SIZE of every architecture. */
#define CMDLINE_SIZE_MAX	8192u

static bool os_release_escapable(char c)
{
	return c == '"' || c == '\\' || c == '$' || c == '`';
}

static int os_release_unquote(const char *value, size_t len,
			      char out[SYSINFO_IMAGE_VALUE_MAX])
{
	bool double_quoted = false;
	size_t n = 0, i;

	if (len >= 2 && value[0] == value[len - 1] &&
	    (value[0] == '"' || value[0] == '\'')) {
		double_quoted = value[0] == '"';
		value++;
		len -= 2;
	}
	for (i = 0; i < len; i++) {
		if (double_quoted && value[i] == '\\' && i + 1 < len &&
		    os_release_escapable(value[i + 1]))
			i++;
		if ((__u8)value[i] < 0x20 || (__u8)value[i] > 0x7e ||
		    n == SYSINFO_IMAGE_VALUE_MAX - 1)
			return -EINVAL;
		out[n++] = value[i];
	}
	if (!n)
		return -EINVAL;
	out[n] = '\0';
	return 0;
}

static void os_release_value(const char *text, size_t len, const char *key,
			     char out[SYSINFO_IMAGE_VALUE_MAX])
{
	const char *end = text + len, *value = NULL, *line, *eol;
	size_t key_len = strlen(key), value_len = 0;

	for (line = text; line < end; line = eol < end ? eol + 1 : end) {
		eol = memchr(line, '\n', (size_t)(end - line));
		if (!eol)
			eol = end;
		if ((size_t)(eol - line) <= key_len ||
		    memcmp(line, key, key_len) || line[key_len] != '=')
			continue;
		value = line + key_len + 1;
		value_len = (size_t)(eol - value);
	}
	if (!value || os_release_unquote(value, value_len, out))
		out[0] = '\0';
}

/* os-release(5): /usr/lib/os-release stands in only where /etc has none. */
static int read_os_release(const char *path, const char *fallback,
			   char **text, size_t *len)
{
	int ret = read_file(path, OS_RELEASE_SIZE_MAX, text, len);

	if (ret == -ENOENT)
		ret = read_file(fallback, OS_RELEASE_SIZE_MAX, text, len);
	return ret;
}

static void read_os_release_value(const char *key,
				  char out[SYSINFO_IMAGE_VALUE_MAX])
{
	size_t len;
	char *text;

	out[0] = '\0';
	if (read_os_release("/etc/os-release", "/usr/lib/os-release", &text,
			    &len))
		return;
	os_release_value(text, len, key, out);
	xfree(text, len + 1);
}

/* /proc/uptime holds the seconds since boot, with a fraction. */
static long read_uptime_sec(void)
{
	char buf[64];
	ssize_t n;
	__u64 sec;
	int fd;

	fd = open("/proc/uptime", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0 || span_to_str(buf, sizeof(buf), buf, (size_t)n))
		return -1;
	if (parse_u64(buf, digits(buf, (size_t)n), LONG_MAX, &sec))
		return -1;
	return (long)sec;
}

/* The number of a "<name>   <n> kB" line of /proc/meminfo, or -1. */
static long meminfo_kb(const char *line, const char *name)
{
	const char *p = str_after_prefix(line, name);
	__u64 kb;

	if (!p)
		return -1;
	while (*p == ' ' || *p == '\t')
		p++;
	if (parse_u64(p, digits(p, strlen(p)), LONG_MAX, &kb))
		return -1;
	return (long)kb;
}

#define MEMINFO_LINE_MAX	255u

static void read_mem(long *total_kb, long *avail_kb)
{
	size_t capacity = 0;
	char *line = NULL;
	FILE *f;
	int got;

	*total_kb = -1;
	*avail_kb = -1;
	f = fopen("/proc/meminfo", "re");
	if (!f)
		return;
	while ((got = read_text_line(f, &line, &capacity,
				     MEMINFO_LINE_MAX)) != 0) {
		if (got == -E2BIG)
			continue;
		if (got < 0)
			break;
		if (*total_kb < 0)
			*total_kb = meminfo_kb(line, "MemTotal:");
		if (*avail_kb < 0)
			*avail_kb = meminfo_kb(line, "MemAvailable:");
		if (*total_kb >= 0 && *avail_kb >= 0)
			break;
	}
	libc_free(line);
	fclose(f);
}

static void read_root_disk(long *total_kb, long *used_kb)
{
	struct statvfs s;
	__u64 tot_b, free_b;

	*total_kb = -1;
	*used_kb = -1;
	if (statvfs("/", &s) != 0)
		return;
	/*
	 * f_frsize is the fragment size statvfs reports its block counts
	 * against; tot/used in raw bytes, then KiB so the JSON wire type
	 * matches mem_*_kb.
	 */
	tot_b  = (__u64)s.f_blocks * s.f_frsize;
	free_b = (__u64)s.f_bfree     * s.f_frsize;
	*total_kb = (long)(tot_b / 1024);
	*used_kb  = (long)((tot_b - free_b) / 1024);
}

struct kernel_config_entry {
	char *key;
	char *value;
};

static int kernel_config_entry_cmp(const void *a, const void *b)
{
	const struct kernel_config_entry *ea = a;
	const struct kernel_config_entry *eb = b;

	return strcmp(ea->key, eb->key);
}

static void kernel_config_entries_free(struct kernel_config_entry *entries,
				       size_t n, size_t cap)
{
	size_t i;

	for (i = 0; i < n; i++) {
		xstrfree(entries[i].key);
		xstrfree(entries[i].value);
	}
	xfree(entries, cap * sizeof(*entries));
}

int sysinfo_kernel_config_foreach(const char *kernel_release,
				  shirudo_kernel_config_cb cb,
				  void *ctx)
{
	struct kernel_config_entry *entries = NULL;
	size_t n = 0, cap = 0, capacity = 0;
	char path[PATH_MAX], *line = NULL;
	FILE *f;
	size_t i;
	int got;

	if (!kernel_release || !kernel_release[0] || !cb ||
	    strsprintf(path, sizeof(path), "/boot/config-%s", kernel_release) < 0)
		return -1;
	f = fopen(path, "re");
	if (!f)
		return -1;
	while ((got = read_text_line(f, &line, &capacity,
				     KCONFIG_LINE_MAX)) != 0) {
		const char *key, *value;

		if (got == -E2BIG)
			continue;
		if (got < 0)
			break;
		if (!kconfig_line(line, &key, &value))
			continue;
		if (n == cap) {
			struct kernel_config_entry *next;
			size_t grown = cap ? 2 * cap : 256;

			next = xreallocarray(entries, cap, grown,
					     sizeof(*entries));
			if (!next) {
				libc_free(line);
				fclose(f);
				kernel_config_entries_free(entries, n, cap);
				return -1;
			}
			entries = next;
			cap = grown;
		}
		entries[n].key = xstrdup(key);
		entries[n].value = xstrdup(value);
		if (!entries[n].key || !entries[n].value) {
			xstrfree(entries[n].key);
			xstrfree(entries[n].value);
			entries[n].key = NULL;
			entries[n].value = NULL;
			libc_free(line);
			fclose(f);
			kernel_config_entries_free(entries, n + 1, cap);
			return -1;
		}
		n++;
	}
	libc_free(line);
	fclose(f);

	if (n)
		qsort(entries, n, sizeof(*entries), kernel_config_entry_cmp);
	for (i = 0; i < n; i++)
		cb(ctx, entries[i].key, entries[i].value);
	kernel_config_entries_free(entries, n, cap);
	return (int)n;
}

static void emit_kernel_config_entry(void *ctx, const char *key,
				     const char *value)
{
	json_key_lossy(ctx, key, strlen(key));
	json_str_lossy(ctx, value, strlen(value));
}

static void emit_kernel_config(struct json_emit *e,
			       const char *kernel_release)
{
	json_obj_open_key(e, "kernel_config");
	sysinfo_kernel_config_foreach(kernel_release,
				      emit_kernel_config_entry, e);

	json_obj_close(e);
}

void sysinfo_gather(struct sysinfo *si)
{
	struct utsname u;

	*si = (struct sysinfo){};
	si->nproc = -1;
	si->mem_total_kb = -1;
	si->mem_avail_kb = -1;
	si->uptime_sec = -1;
	si->disk_total_kb = -1;
	si->disk_used_kb = -1;

	if (gethostname(si->hostname, sizeof(si->hostname)) != 0)
		si->hostname[0] = '\0';
	si->hostname[sizeof(si->hostname) - 1] = '\0';

	if (uname(&u) == 0) {
		if (strscpy(si->kernel_release, u.release,
			    sizeof(si->kernel_release)) < 0)
			si->kernel_release[0] = '\0';
		if (strscpy(si->kernel_version, u.version,
			    sizeof(si->kernel_version)) < 0)
			si->kernel_version[0] = '\0';
		if (strscpy(si->machine, u.machine, sizeof(si->machine)) < 0)
			si->machine[0] = '\0';
		if (si->hostname[0] == '\0' &&
		    strscpy(si->hostname, u.nodename, sizeof(si->hostname)) < 0)
			si->hostname[0] = '\0';
	}

	read_os_release_value("PRETTY_NAME", si->os_pretty);
	read_first_line("/etc/machine-id", si->machine_id,
			sizeof(si->machine_id));
	read_first_line("/proc/sys/kernel/random/boot_id", si->boot_id,
			sizeof(si->boot_id));
	kernel_build_id_read(si->kernel_build_id);

	si->nproc = sysconf(_SC_NPROCESSORS_ONLN);
	read_mem(&si->mem_total_kb, &si->mem_avail_kb);
	read_root_disk(&si->disk_total_kb, &si->disk_used_kb);
	si->uptime_sec = read_uptime_sec();
}

static bool cmdline_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n';
}

static int image_root_normalise(const char *arg, size_t len,
				char out[SYSINFO_IMAGE_ROOT_MAX])
{
	size_t i;

	if (len != SYSINFO_IMAGE_ROOT_MAX - 1)
		return -EINVAL;
	for (i = 0; i < len; i++) {
		if (!isxdigit((__u8)arg[i]))
			return -EINVAL;
		out[i] = (char)tolower((__u8)arg[i]);
	}
	out[len] = '\0';
	return 0;
}

struct cmdline_arg {
	const char *value;
	size_t len;
};

static void cmdline_arg_match(const char *arg, size_t len, const char *key,
			      struct cmdline_arg *found)
{
	size_t key_len = strlen(key);

	if (len < key_len || memcmp(arg, key, key_len))
		return;
	found->value = arg + key_len;
	found->len = len - key_len;
}

static void cmdline_image_root(const char *cmdline, size_t len,
			       char out[SYSINFO_IMAGE_ROOT_MAX])
{
	const char *end = cmdline + len, *arg, *arg_end;
	struct cmdline_arg roothash = {}, usrhash = {};
	const struct cmdline_arg *hash;

	for (arg = cmdline; arg < end; arg = arg_end) {
		while (arg < end && cmdline_space(*arg))
			arg++;
		arg_end = arg;
		while (arg_end < end && !cmdline_space(*arg_end))
			arg_end++;
		cmdline_arg_match(arg, (size_t)(arg_end - arg), "roothash=",
				  &roothash);
		cmdline_arg_match(arg, (size_t)(arg_end - arg), "usrhash=",
				  &usrhash);
	}
	hash = roothash.value ? &roothash : &usrhash;
	if (!hash->value || image_root_normalise(hash->value, hash->len, out))
		out[0] = '\0';
}

void sysinfo_image_read_at(const char *os_release,
			   const char *os_release_fallback,
			   const char *cmdline, struct sysinfo_image *img)
{
	char line[CMDLINE_SIZE_MAX] = {};
	size_t len;
	char *text;

	*img = (struct sysinfo_image){};
	if (!read_os_release(os_release, os_release_fallback, &text, &len)) {
		os_release_value(text, len, "IMAGE_ID", img->id);
		os_release_value(text, len, "IMAGE_VERSION", img->version);
		xfree(text, len + 1);
	}
	read_first_line(cmdline, line, sizeof(line));
	len = strlen(line);
	if (len < sizeof(line) - 1)
		cmdline_image_root(line, len, img->root);
}

void sysinfo_image_read(struct sysinfo_image *img)
{
	sysinfo_image_read_at("/etc/os-release", "/usr/lib/os-release",
			      "/proc/cmdline", img);
}

void sysinfo_emit_json(struct json_emit *e,
		       const struct sysinfo *si)
{
	json_obj_open_key(e, "system");
	json_kv_string_lossy(e, "hostname", si->hostname);
	json_kv_string_lossy(e, "os", si->os_pretty);
	json_kv_string_lossy(e, "kernel_release", si->kernel_release);
	json_kv_string_lossy(e, "kernel_version", si->kernel_version);
	json_kv_string(e, "kernel_build_id", si->kernel_build_id);
	emit_kernel_config(e, si->kernel_release);
	json_kv_string_lossy(e, "architecture", si->machine);
	json_kv_string_lossy(e, "machine_id", si->machine_id);
	json_kv_string_lossy(e, "boot_id", si->boot_id);
	json_kv_int(e, "nproc", si->nproc);
	json_kv_int(e, "mem_total_kb", si->mem_total_kb);
	json_kv_int(e, "mem_avail_kb", si->mem_avail_kb);
	json_kv_int(e, "disk_total_kb", si->disk_total_kb);
	json_kv_int(e, "disk_used_kb", si->disk_used_kb);
	json_kv_int(e, "uptime_seconds", si->uptime_sec);
	json_obj_close(e);
}
