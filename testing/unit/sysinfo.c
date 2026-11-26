// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "sysinfo.h"
#include "unit.h"

#define ROOT_LOWER \
	"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"
#define ROOT_UPPER \
	"A3C3F1B0E4C2D7F09E3B6B2A8B1D5E7C4F6A9D0B2C8E1F3A5B7D9C0E2F4A6B8C"
#define USR_LOWER \
	"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807"

static char dir[4096], etc_path[4200], usr_path[4200], cmdline_path[4200];

static void use_fixtures(void)
{
	const char *tmp = getenv("TMPDIR");

	ASSERT_TRUE(strsprintf(dir, sizeof(dir),
			       "%s/shirudo-unit-sysinfo-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(dir));
	ASSERT_TRUE(strsprintf(etc_path, sizeof(etc_path),
			       "%s/etc-os-release", dir) > 0);
	ASSERT_TRUE(strsprintf(usr_path, sizeof(usr_path),
			       "%s/usr-lib-os-release", dir) > 0);
	ASSERT_TRUE(strsprintf(cmdline_path, sizeof(cmdline_path),
			       "%s/cmdline", dir) > 0);
}

static void drop_fixtures(void)
{
	unlink(etc_path);
	unlink(usr_path);
	unlink(cmdline_path);
	rmdir(dir);
}

static void write_fixture(const char *path, const char *text, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, text, len), 0);
	ASSERT_EQ(close(fd), 0);
}

/* A path left NULL names a file that does not exist. */
static struct sysinfo_image image_of(const char *etc, const char *usr,
				     const char *cmdline)
{
	struct sysinfo_image img;

	use_fixtures();
	if (etc)
		write_fixture(etc_path, etc, strlen(etc));
	if (usr)
		write_fixture(usr_path, usr, strlen(usr));
	if (cmdline)
		write_fixture(cmdline_path, cmdline, strlen(cmdline));
	sysinfo_image_read_at(etc_path, usr_path, cmdline_path, &img);
	drop_fixtures();
	return img;
}

static void unquoted_values_are_copied(void)
{
	struct sysinfo_image img;

	img = image_of("NAME=Fleet\nIMAGE_ID=fleet-os\n"
		       "IMAGE_VERSION=2026.11.1\n", NULL, NULL);
	EXPECT_STREQ(img.id, "fleet-os");
	EXPECT_STREQ(img.version, "2026.11.1");
	EXPECT_STREQ(img.root, "");
}

static void one_pair_of_matching_quotes_is_stripped(void)
{
	struct sysinfo_image img;

	img = image_of("IMAGE_ID=\"fleet os\"\nIMAGE_VERSION='2026 \"11\"'\n",
		       NULL, NULL);
	EXPECT_STREQ(img.id, "fleet os");
	EXPECT_STREQ(img.version, "2026 \"11\"");

	img = image_of("IMAGE_ID=\"\"fleet\"\"\nIMAGE_VERSION=\"2026'\n",
		       NULL, NULL);
	EXPECT_STREQ(img.id, "\"fleet\"");
	EXPECT_STREQ(img.version, "\"2026'");
}

static void double_quotes_drop_the_escaping_backslash(void)
{
	struct sysinfo_image img;

	img = image_of("IMAGE_ID=\"a\\\"b\\\\c\\$d\\`e\\nf\"\n"
		       "IMAGE_VERSION='a\\\"b'\n", NULL, NULL);
	EXPECT_STREQ(img.id, "a\"b\\c$d`e\\nf");
	EXPECT_STREQ(img.version, "a\\\"b");

	img = image_of("IMAGE_ID=a\\\"b\n", NULL, NULL);
	EXPECT_STREQ(img.id, "a\\\"b");
}

static void missing_key_is_absent(void)
{
	struct sysinfo_image img;

	img = image_of("NAME=Fleet\nXIMAGE_ID=no\nIMAGE_ID_LIKE=no\n"
		       "#IMAGE_ID=no\nIMAGE_VERSION=7\n", NULL, NULL);
	EXPECT_STREQ(img.id, "");
	EXPECT_STREQ(img.version, "7");

	img = image_of(NULL, NULL, NULL);
	EXPECT_STREQ(img.id, "");
	EXPECT_STREQ(img.version, "");
}

static void empty_value_is_absent(void)
{
	struct sysinfo_image img;

	img = image_of("IMAGE_ID=\nIMAGE_VERSION=\"\"\n", NULL, NULL);
	EXPECT_STREQ(img.id, "");
	EXPECT_STREQ(img.version, "");
}

static void last_assignment_counts(void)
{
	struct sysinfo_image img;

	img = image_of("IMAGE_ID=first\nIMAGE_ID=second\n"
		       "IMAGE_VERSION=1\nIMAGE_VERSION=caf\xc3\xa9", NULL,
		       NULL);
	EXPECT_STREQ(img.id, "second");
	EXPECT_STREQ(img.version, "");
}

static void usr_lib_is_read_when_etc_does_not_exist(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, "IMAGE_ID=from-usr\nIMAGE_VERSION=2\n", NULL);
	EXPECT_STREQ(img.id, "from-usr");
	EXPECT_STREQ(img.version, "2");

	img = image_of("IMAGE_ID=from-etc\n",
		       "IMAGE_ID=from-usr\nIMAGE_VERSION=2\n", NULL);
	EXPECT_STREQ(img.id, "from-etc");
	EXPECT_STREQ(img.version, "");
}

static void value_longer_than_255_bytes_is_absent(void)
{
	char text[600], longest[256], too_long[257];
	struct sysinfo_image img;

	memset(longest, 'a', sizeof(longest) - 1);
	longest[sizeof(longest) - 1] = '\0';
	memset(too_long, 'b', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';
	ASSERT_TRUE(strsprintf(text, sizeof(text),
			       "IMAGE_ID=\"%s\"\nIMAGE_VERSION=%s\n", longest,
			       too_long) > 0);
	img = image_of(text, NULL, NULL);
	EXPECT_STREQ(img.id, longest);
	EXPECT_STREQ(img.version, "");
}

static void value_outside_printable_ascii_is_absent(void)
{
	struct sysinfo_image img;

	img = image_of("IMAGE_ID=caf\xc3\xa9\nIMAGE_VERSION=1\t2\n", NULL,
		       NULL);
	EXPECT_STREQ(img.id, "");
	EXPECT_STREQ(img.version, "");

	img = image_of("IMAGE_ID=fleet\r\nIMAGE_VERSION=1\x7f\n", NULL, NULL);
	EXPECT_STREQ(img.id, "");
	EXPECT_STREQ(img.version, "");
}

static void value_with_a_nul_is_absent(void)
{
	static const char text[] = "IMAGE_ID=fle\0et\nIMAGE_VERSION=3\n";
	struct sysinfo_image img;

	use_fixtures();
	write_fixture(etc_path, text, sizeof(text) - 1);
	sysinfo_image_read_at(etc_path, usr_path, cmdline_path, &img);
	drop_fixtures();
	EXPECT_STREQ(img.id, "");
	EXPECT_STREQ(img.version, "3");
}

static void roothash_wins_over_usrhash(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, NULL,
		       "quiet usrhash=" USR_LOWER " roothash=" ROOT_LOWER
		       " ro\n");
	EXPECT_STREQ(img.root, ROOT_LOWER);

	img = image_of(NULL, NULL,
		       "roothash=" ROOT_LOWER " usrhash=" USR_LOWER "\n");
	EXPECT_STREQ(img.root, ROOT_LOWER);
}

static void usrhash_is_used_without_roothash(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, NULL,
		       "BOOT_IMAGE=/vmlinuz xroothash=" ROOT_LOWER
		       "\tusrhash=" USR_LOWER);
	EXPECT_STREQ(img.root, USR_LOWER);
}

static void hash_is_normalised_to_lowercase(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, NULL, "roothash=" ROOT_UPPER "\n");
	EXPECT_STREQ(img.root, ROOT_LOWER);
}

static void malformed_hash_is_absent(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, NULL, "roothash=abc123\n");
	EXPECT_STREQ(img.root, "");
	img = image_of(NULL, NULL, "roothash=" ROOT_LOWER "0\n");
	EXPECT_STREQ(img.root, "");
	img = image_of(NULL, NULL, "roothash=g" USR_LOWER "\n");
	EXPECT_STREQ(img.root, "");
	img = image_of(NULL, NULL, "roothash=\"" ROOT_LOWER "\"\n");
	EXPECT_STREQ(img.root, "");
	img = image_of(NULL, NULL, "roothash=sha256:" ROOT_LOWER "\n");
	EXPECT_STREQ(img.root, "");
}

static void malformed_roothash_does_not_fall_back_to_usrhash(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, NULL,
		       "roothash=abc123 usrhash=" USR_LOWER "\n");
	EXPECT_STREQ(img.root, "");
}

static void no_hash_is_absent(void)
{
	struct sysinfo_image img;

	img = image_of(NULL, NULL, "BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro\n");
	EXPECT_STREQ(img.root, "");
	img = image_of(NULL, NULL, "");
	EXPECT_STREQ(img.root, "");
	img = image_of("IMAGE_ID=fleet-os\n", NULL, NULL);
	EXPECT_STREQ(img.id, "fleet-os");
	EXPECT_STREQ(img.root, "");
}

static void command_line_that_does_not_fit_is_absent(void)
{
	static char cmdline[8192 + 128];
	struct sysinfo_image img;
	size_t used;

	memset(cmdline, 'x', sizeof(cmdline));
	used = sizeof(cmdline) - sizeof(" roothash=" ROOT_LOWER);
	memcpy(cmdline + used, " roothash=" ROOT_LOWER,
	       sizeof(" roothash=" ROOT_LOWER));
	img = image_of(NULL, NULL, cmdline);
	EXPECT_STREQ(img.root, "");

	memset(cmdline, 'x', sizeof(cmdline));
	memcpy(cmdline, "roothash=" ROOT_LOWER " ",
	       sizeof("roothash=" ROOT_LOWER " ") - 1);
	cmdline[sizeof(cmdline) - 1] = '\0';
	img = image_of(NULL, NULL, cmdline);
	EXPECT_STREQ(img.root, "");
}

/* A NUL would end the line short of the bytes the kernel wrote. */
static void command_line_with_a_nul_is_absent(void)
{
	static const char text[] = "roothash=" ROOT_LOWER "\0 ro\n";
	struct sysinfo_image img;

	use_fixtures();
	write_fixture(cmdline_path, text, sizeof(text) - 1);
	sysinfo_image_read_at(etc_path, usr_path, cmdline_path, &img);
	drop_fixtures();
	EXPECT_STREQ(img.root, "");
}

/* The kernel and the files give bytes: a stray one costs no document. */
static void system_text_that_is_no_utf8_is_written(void)
{
	struct sysinfo si = { .nproc = -1, .mem_total_kb = -1 };
	char buf[4096];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	strscpy_literal(si.hostname, "node\xff");
	strscpy_literal(si.kernel_release, "7.0\xc3");
	strscpy_literal(si.machine, "x86_64\xc0\xaf");
	strscpy_literal(si.boot_id, "\xfe");
	json_obj_open(&e);
	sysinfo_emit_json(&e, &si);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
	EXPECT_TRUE(str_contains(buf, "\"hostname\":\"node\\ufffd\""));
	EXPECT_TRUE(str_contains(buf, "\"kernel_release\":\"7.0\\ufffd\""));
	EXPECT_TRUE(str_contains(buf,
				 "\"architecture\":\"x86_64\\ufffd\\ufffd\""));
	EXPECT_TRUE(str_contains(buf, "\"boot_id\":\"\\ufffd\""));
	EXPECT_TRUE(str_contains(buf, "\"kernel_config\":{}"));
}

static void memory_of_this_host_is_read(void)
{
	struct sysinfo si;

	sysinfo_gather(&si);
	EXPECT_GT(si.mem_total_kb, 0);
	EXPECT_TRUE(si.mem_avail_kb >= 0 &&
		    si.mem_avail_kb <= si.mem_total_kb);
}

static const struct unit_case cases[] = {
	UNIT_CASE(unquoted_values_are_copied),
	UNIT_CASE(one_pair_of_matching_quotes_is_stripped),
	UNIT_CASE(double_quotes_drop_the_escaping_backslash),
	UNIT_CASE(missing_key_is_absent),
	UNIT_CASE(empty_value_is_absent),
	UNIT_CASE(last_assignment_counts),
	UNIT_CASE(usr_lib_is_read_when_etc_does_not_exist),
	UNIT_CASE(value_longer_than_255_bytes_is_absent),
	UNIT_CASE(value_outside_printable_ascii_is_absent),
	UNIT_CASE(value_with_a_nul_is_absent),
	UNIT_CASE(roothash_wins_over_usrhash),
	UNIT_CASE(usrhash_is_used_without_roothash),
	UNIT_CASE(hash_is_normalised_to_lowercase),
	UNIT_CASE(malformed_hash_is_absent),
	UNIT_CASE(malformed_roothash_does_not_fall_back_to_usrhash),
	UNIT_CASE(no_hash_is_absent),
	UNIT_CASE(command_line_that_does_not_fit_is_absent),
	UNIT_CASE(command_line_with_a_nul_is_absent),
	UNIT_CASE(system_text_that_is_no_utf8_is_written),
	UNIT_CASE(memory_of_this_host_is_read),
	{}
};

UNIT_SUITE(sysinfo, cases);
