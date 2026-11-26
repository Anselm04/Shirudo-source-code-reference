// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read back the integrity counters init pinned in the private bpffs.
 */
#include <shirudo/misc.h>

#include "identity.h"
#include "integrity.h"
#include "tamper.h"

static const struct {
	const char	*name;
	const char	*meaning;
} integrity_points[INTEGRITY_MAX] = {
	[INTEGRITY_MODULE_SIGNATURE] = { "ModuleSignature",
		"module load without a valid signature" },
	[INTEGRITY_DEV_MEM] = { "DevMem",
		"/dev/mem or /dev/port" },
	[INTEGRITY_EFI_TEST] = { "EfiTest",
		"EFI runtime services through efi_test" },
	[INTEGRITY_KEXEC] = { "KexecSignature",
		"kexec of a kernel without a valid signature" },
	[INTEGRITY_PCI_ACCESS] = { "PciAccess",
		"PCI configuration write or BAR mapping" },
	[INTEGRITY_IOPORT] = { "IoPort",
		"raw I/O port access" },
	[INTEGRITY_MSR] = { "Msr",
		"model-specific register write" },
	[INTEGRITY_ACPI_TABLES] = { "AcpiTables",
		"ACPI table override or custom method" },
	[INTEGRITY_DEVICE_TREE] = { "DeviceTree",
		"device tree overlay" },
	[INTEGRITY_PCMCIA_CIS] = { "PcmciaCis",
		"PCMCIA CIS override" },
	[INTEGRITY_TIOCSSERIAL] = { "Tiocsserial",
		"serial port I/O or IRQ reconfiguration" },
	[INTEGRITY_MODULE_PARAMETERS] = { "ModuleParameters",
		"module parameter that sets hardware addresses" },
	[INTEGRITY_MMIOTRACE] = { "Mmiotrace",
		"MMIO tracing" },
	[INTEGRITY_DEBUGFS] = { "Debugfs",
		"debugfs file that writes or maps" },
	[INTEGRITY_XMON_WR] = { "XmonWrite",
		"xmon write access" },
	[INTEGRITY_BPF_WRITE_USER] = { "BpfWriteUser",
		"BPF program that writes user memory" },
	[INTEGRITY_DBG_WRITE_KERNEL] = { "DbgWriteKernel",
		"kernel debugger write" },
	[INTEGRITY_RTAS_ERROR_INJECTION] = { "RtasErrorInjection",
		"RTAS error injection" },
	[INTEGRITY_XEN_USER_ACTIONS] = { "XenUserActions",
		"Xen user action that writes memory" },
	[INTEGRITY_KCORE] = { "Kcore",
		"/proc/kcore, the kernel's memory" },
	[INTEGRITY_HIBERNATE_LOCATION] = { "HibernateLocation",
		"EFI variable naming a resume device" },
	[INTEGRITY_OTHER] = { "Other",
		"lockdown reason this build does not name" },
};

const char *integrity_name(enum integrity_point point)
{
	if (point >= INTEGRITY_MAX || !integrity_points[point].name)
		return "?";
	return integrity_points[point].name;
}

const char *integrity_meaning(enum integrity_point point)
{
	if (point >= INTEGRITY_MAX || !integrity_points[point].meaning)
		return "?";
	return integrity_points[point].meaning;
}

int integrity_read(struct integrity_counts *out)
{
	return counters_read(&shirudo_guard_maps[GUARD_INTEGRITY],
			     INTEGRITY_MAX, out->count, &out->total);
}
