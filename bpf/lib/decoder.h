/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The decoder manifest a BPF program declares in .rodata.
 */

#ifndef SHIRUDO_DECODER_H
#define SHIRUDO_DECODER_H

#define DECODER_MANIFEST_MAGIC	0x44434544u	/* "DECD" le */
#define UPATCH_DECODER_VERSION	1u
#define UPATCH_DECODER_LANG_LUA	1u
#define UPATCH_DECODER_INPUT_MAP_V1 1u
#define UPATCH_DECODER_EXPORT_LOG 1u
#define UPATCH_DECODER_EXPORT_METRIC 2u

struct decoder_manifest {
	__u32	magic;		/* DECODER_MANIFEST_MAGIC */
	__u16	version;		/* UPATCH_DECODER_VERSION */
	__u16	language;	/* UPATCH_DECODER_LANG_* */
	__u16	api_version;
	__u16	input_format;	/* UPATCH_DECODER_INPUT_MAP_V1 */
	__u16	export_signal;	/* UPATCH_DECODER_EXPORT_* */
	__u16	reserved;
	char	upatch[64];	/* empty, or the upatch's name */
	char	map[16];
	char	source[64];
	char	entrypoint[32];
};

#endif /* SHIRUDO_DECODER_H */
