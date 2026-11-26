..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, security reviewers

Integrity counters
==================

The tamper counters count attempts on shirudo's own state. The
integrity counters count attempts on the running kernel: each way root
has to change or read it that ``bpf2`` refuses, what lockdown in
integrity mode refuses, ``/proc/kcore`` and the resume location, has a
counter, and the guard adds one to it when it refuses. The counters
live in the array map ``shirudo_integrity``, which ``init`` creates,
freezes and pins at ``/run/shirudo/bpffs/integrity`` at every boot, so
they count this boot's refusals. No task resets them from userspace;
only the hooks add to them. Threat T6 of the :doc:`threat-model` says
what the guards keep, and T10 why they count.

Counters
--------

The name and the meaning are what ``shirudo status`` prints. Each
counter but ``HibernateLocation`` is a lockdown reason the kernel asks
``lsm/locked_down`` about, refused with ``EPERM`` to every caller,
shirudo's own tasks included.

.. list-table::
   :header-rows: 1
   :widths: 22 33 45

   * - Counter
     - Meaning
     - Reason and condition
   * - ``ModuleSignature``
     - module load without a valid signature
     - ``LOCKDOWN_MODULE_SIGNATURE``: a module whose signature is
       missing or the kernel cannot verify, or one loaded with
       ``MODULE_INIT_IGNORE_MODVERSIONS`` or
       ``MODULE_INIT_IGNORE_VERMAGIC``, on a kernel that does not
       refuse it itself
   * - ``DevMem``
     - ``/dev/mem`` or ``/dev/port``
     - ``LOCKDOWN_DEV_MEM``: an open of one of them
   * - ``EfiTest``
     - EFI runtime services through ``efi_test``
     - ``LOCKDOWN_EFI_TEST``: an open of ``/dev/efi_test``
   * - ``KexecSignature``
     - kexec of a kernel without a valid signature
     - ``LOCKDOWN_KEXEC``. ``lsm/kernel_load_data`` and
       ``lsm/kernel_read_file`` refuse every kexec image before the
       kernel asks, counted as the tamper counter ``Kexec``, so this
       counter does not move.
   * - ``PciAccess``
     - PCI configuration write or BAR mapping
     - ``LOCKDOWN_PCI_ACCESS``: a write of a device's ``config`` or a
       map of its ``resource`` files, ``/proc/bus/pci``
   * - ``IoPort``
     - raw I/O port access
     - ``LOCKDOWN_IOPORT``: ``ioperm(2)`` and ``iopl(2)``
   * - ``Msr``
     - model-specific register write
     - ``LOCKDOWN_MSR``: a write of ``/dev/cpu/*/msr``
   * - ``AcpiTables``
     - ACPI table override or custom method
     - ``LOCKDOWN_ACPI_TABLES``
   * - ``DeviceTree``
     - device tree overlay
     - ``LOCKDOWN_DEVICE_TREE``
   * - ``PcmciaCis``
     - PCMCIA CIS override
     - ``LOCKDOWN_PCMCIA_CIS``
   * - ``Tiocsserial``
     - serial port I/O or IRQ reconfiguration
     - ``LOCKDOWN_TIOCSSERIAL``: ``TIOCSSERIAL`` that changes the port,
       as ``setserial`` makes
   * - ``ModuleParameters``
     - module parameter that sets hardware addresses
     - ``LOCKDOWN_MODULE_PARAMETERS``
   * - ``Mmiotrace``
     - MMIO tracing
     - ``LOCKDOWN_MMIOTRACE``
   * - ``Debugfs``
     - debugfs file that writes or maps
     - ``LOCKDOWN_DEBUGFS``: an open of a debugfs file that can be
       written, mapped or given an ioctl, even for reading
   * - ``XmonWrite``
     - xmon write access
     - ``LOCKDOWN_XMON_WR``, powerpc only
   * - ``BpfWriteUser``
     - BPF program that writes user memory
     - ``LOCKDOWN_BPF_WRITE_USER``: a program that calls
       ``bpf_probe_write_user()``, at its load
   * - ``DbgWriteKernel``
     - kernel debugger write
     - ``LOCKDOWN_DBG_WRITE_KERNEL``
   * - ``RtasErrorInjection``
     - RTAS error injection
     - ``LOCKDOWN_RTAS_ERROR_INJECTION``, powerpc only
   * - ``XenUserActions``
     - Xen user action that writes memory
     - ``LOCKDOWN_XEN_USER_ACTIONS``
   * - ``Kcore``
     - ``/proc/kcore``, the kernel's memory
     - ``LOCKDOWN_KCORE``: an open of ``/proc/kcore``, which integrity
       mode leaves readable
   * - ``HibernateLocation``
     - EFI variable naming a resume device
     - ``lsm/file_open``: an open of a ``HibernateLocation`` variable
       on efivarfs for writing, from which the next boot's initrd would
       resume
   * - ``Other``
     - lockdown reason this build does not name
     - A reason of integrity mode that a later kernel adds

The hibernation check, ``LOCKDOWN_HIBERNATION``, is refused without a
count: every read of ``/sys/power/state`` makes it.

Reading the counters
--------------------

``shirudo status``, started from the runtime image as for the tamper
counters, prints the section ``Integrity attempts (this boot):`` after
``Tamper attempts (this boot):``, with one line per counter that is not
zero: its name, its count and its meaning. It prints ``none`` when
every counter is zero, ``none recorded before init`` before ``init``
has pinned the map, and ``unavailable:`` with the error when the map
cannot be read.

``shirudo status --json`` carries every counter under
``integrity_attempts``, with the sum in ``total`` and each counter by
name in ``counters``, ``null`` before ``init`` has pinned the map.

The keepalive, ``shirudo status --otel``, carries every counter in the
``integrity`` list of its body, after ``tamper``, zeros included and in
the order of this page, and the TPM quotes the body. The list is
``null``, and bit 6 of the body's ``flags`` set, when the counters
cannot be read.

What a non-zero counter means
-----------------------------

A counter that moved means that ``bpf2`` refused a change or a read of
the running kernel this boot: the operation did not happen. It does not
mean that the kernel is compromised, nor that root made the attempt:
honest tools move some counters. ``Debugfs`` moves when a tool opens a
writable debugfs file to read it, ``Tiocsserial`` when ``setserial``
reconfigures a port, and ``ModuleSignature`` on ``modprobe --force``,
which makes a signed module count as unsigned.

A counter does not change the verdict of ``shirudo status``, as a tamper
counter does not. To act on one, see
:doc:`/operate/troubleshoot/incident-tampered`.

Related
-------

- :doc:`tamper-counters` for the attempts on shirudo's own state
- :doc:`threat-model`, threats T6 and T10
- :doc:`/internals/enforcement` for the hooks
