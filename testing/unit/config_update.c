// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "chain.h"
#include "config_update.h"
#include "unit.h"

#define PCR	12

static struct {
	__u32 reset;
	__u32 restart;
	__u8 pcr[32];
	__u32 extends;
	enum config_update_checkpoint fail_at;
} tpm;

static char dir[4096];

static int fake_identity(void *ctx, __u32 *reset, __u32 *restart)
{
	*reset = tpm.reset;
	*restart = tpm.restart;
	return 0;
}

static int fake_pcr_read(void *ctx, __u32 pcr, __u8 out[32])
{
	memcpy(out, tpm.pcr, sizeof(tpm.pcr));
	return 0;
}

static int fake_pcr_extend(void *ctx, __u32 pcr, const __u8 event[32])
{
	tpm.extends++;
	return chain_fold(tpm.pcr, event);
}

static int fake_target(void *ctx, const struct config_update_target *target)
{
	return 0;
}

static int fake_seal(void *ctx, int fd)
{
	return 0;
}

static int fake_checkpoint(void *ctx, enum config_update_checkpoint at)
{
	return at == tpm.fail_at ? -ECANCELED : 0;
}

static const struct config_update_ops ops = {
	.boot_identity = fake_identity,
	.pcr_read = fake_pcr_read,
	.pcr_extend = fake_pcr_extend,
	.prepare = fake_target,
	.activate = fake_target,
	.seal = fake_seal,
	.checkpoint = fake_checkpoint,
};

static struct config_update_target target(char id)
{
	struct config_update_target t = {};

	ASSERT_TRUE(strsprintf(t.prefix, sizeof(t.prefix),
			       "/verified/config-%c", id) > 0);
	memset(t.root_hash, id, sizeof(t.root_hash));
	return t;
}

/* A fresh journal and a TPM in its first boot. */
static void use_journal(void)
{
	const char *tmp = getenv("TMPDIR");

	memset(&tpm, 0, sizeof(tpm));
	tpm.reset = 1;
	ASSERT_TRUE(strsprintf(dir, sizeof(dir),
			       "%s/shirudo-unit-config-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(dir));
}

static void drop_journal(void)
{
	static const char *const names[] = {
		"state", "events", "lock", "next-boot", ".state.tmp",
		".next-boot.tmp",
	};
	char path[4200];

	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		if (strsprintf(path, sizeof(path), "%s/%s", dir,
			       names[i]) > 0)
			unlink(path);
	}
	rmdir(dir);
}

/* One run of init, as image_boot() and image_boot_complete() drive it. */
static int init(char id)
{
	struct config_update_target t = target(id);
	struct config_update update;
	int ret;

	ret = config_update_open(dir, &ops, NULL, &update);
	if (ret)
		return ret;
	ret = config_update_boot(&update, &t, PCR);
	if (!ret)
		ret = config_update_complete_boot(&update);
	config_update_close(&update);
	return ret;
}

static int update(char id)
{
	struct config_update_target t = target(id);
	struct config_update update;
	int ret;

	ret = config_update_open(dir, &ops, NULL, &update);
	if (ret)
		return ret;
	ret = config_update_begin(&update, &t, PCR);
	config_update_close(&update);
	return ret;
}

static int stage(char id)
{
	struct config_update_target t = target(id);
	struct config_update update;
	int ret;

	ret = config_update_open(dir, &ops, NULL, &update);
	if (ret)
		return ret;
	ret = config_update_stage(&update, &t);
	config_update_close(&update);
	return ret;
}

static int check(void)
{
	struct config_update update;
	int ret;

	ret = config_update_open(dir, &ops, NULL, &update);
	if (ret)
		return ret;
	ret = config_update_check(&update, NULL);
	config_update_close(&update);
	return ret;
}

/* boot_target()'s question: does the stage take the next init? */
static int staged(void)
{
	struct config_update_record previous;
	struct config_update_target t;
	struct config_update update;
	int ret;

	ret = config_update_open(dir, &ops, NULL, &update);
	if (ret)
		return ret;
	ret = config_update_read(&update, &previous);
	if (!ret)
		ret = config_update_staged(&update, &previous, tpm.reset, &t);
	config_update_close(&update);
	return ret;
}

static __s64 sequence(void)
{
	struct config_update_record record;
	struct config_update update;

	ASSERT_EQ(config_update_open(dir, &ops, NULL, &update), 0);
	ASSERT_EQ(config_update_read(&update, &record), 0);
	config_update_close(&update);
	return record.sequence;
}

/* A suspend to RAM: the TPM resumes with its PCRs and counts a restart. */
static void resume(void)
{
	tpm.restart++;
}

/* A TPM restart without a reboot clears the PCRs as well. */
static void restart(void)
{
	tpm.restart++;
	memset(tpm.pcr, 0, sizeof(tpm.pcr));
}

static void reboot(void)
{
	tpm.reset++;
	tpm.restart = 0;
	memset(tpm.pcr, 0, sizeof(tpm.pcr));
}

/* An activation stopped after its extension stays pending across a resume. */
static void resume_keeps_pending_activation(void)
{
	__u32 extends;

	use_journal();
	ASSERT_EQ(init('A'), 0);
	tpm.fail_at = CONFIG_CHECK_EXTEND;
	ASSERT_EQ(update('B'), -ECANCELED);
	tpm.fail_at = 0;
	resume();
	extends = tpm.extends;
	EXPECT_EQ(init('B'), -EINPROGRESS);
	EXPECT_EQ(check(), -EINPROGRESS);
	EXPECT_EQ(tpm.extends, extends);
	reboot();
	EXPECT_EQ(init('B'), 0);
	EXPECT_EQ(check(), 0);
	drop_journal();
}

/* After a resume the record is of this boot, and init re-runs as in it. */
static void resume_keeps_completed_selection(void)
{
	__u32 extends;
	__s64 seq;

	use_journal();
	ASSERT_EQ(init('A'), 0);
	seq = sequence();
	resume();
	extends = tpm.extends;
	EXPECT_EQ(check(), 0);
	EXPECT_EQ(init('A'), 0);
	EXPECT_EQ(tpm.extends, extends);
	EXPECT_EQ(sequence(), seq);
	EXPECT_EQ(init('B'), -EBUSY);
	EXPECT_EQ(update('B'), 0);
	EXPECT_EQ(check(), 0);
	drop_journal();
}

/* A TPM restart clears the config PCR: refused until the reboot. */
static void restart_refuses_until_reboot(void)
{
	__u32 extends;

	use_journal();
	ASSERT_EQ(init('A'), 0);
	restart();
	extends = tpm.extends;
	EXPECT_EQ(check(), -EUCLEAN);
	EXPECT_EQ(init('A'), -EUCLEAN);
	EXPECT_EQ(tpm.extends, extends);
	reboot();
	EXPECT_EQ(init('A'), 0);
	EXPECT_EQ(check(), 0);
	drop_journal();
}

/* A stage waits for a new reset count; a resume is none. */
static void stage_waits_for_reboot(void)
{
	use_journal();
	ASSERT_EQ(init('A'), 0);
	ASSERT_EQ(stage('B'), 0);
	resume();
	EXPECT_EQ(staged(), 0);
	EXPECT_EQ(init('A'), 0);
	reboot();
	EXPECT_EQ(staged(), 1);
	EXPECT_EQ(init('B'), 0);
	EXPECT_EQ(check(), 0);
	drop_journal();
}

static const struct unit_case cases[] = {
	UNIT_CASE(resume_keeps_pending_activation),
	UNIT_CASE(resume_keeps_completed_selection),
	UNIT_CASE(restart_refuses_until_reboot),
	UNIT_CASE(stage_waits_for_reboot),
	{}
};

UNIT_SUITE(config_update, cases);
