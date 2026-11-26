..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Boot process and measured boot
==============================

shirudo starts enforcement from the initrd, and everything it trusts
at that point came from the boot chain before it. This page explains
how a UEFI machine gets from power-on to the initrd, how Secure Boot
decides what may run, how measured boot records what did run, and
which component writes which TPM PCR. It ends with what shirudo takes
from each of these and where that stops.

From power-on to the initrd
---------------------------

Each stage of a boot runs code that the previous stage chose. The UEFI
firmware starts a boot loader from the EFI system partition, the boot
loader starts the kernel with a command line and an initrd, and the
initrd mounts the root file system and hands over to it. Whatever runs
``shirudo init`` in the initrd is only as trustworthy as every stage
that led to it.

Two mechanisms address this, and they answer different questions.
Secure Boot decides whether a stage may run at all. Measured boot
records what ran, so that someone else can decide afterwards whether
they trust it. A target needs both: Secure Boot keeps unsigned code
from starting, and measurements let a remote verifier tell which
signed code started.

Secure Boot, shim and MOK
-------------------------

With Secure Boot enabled, the firmware checks the signature of every
UEFI executable it starts against its signature database ``db`` and
refuses anything listed in the forbidden database ``dbx``. The
platform key ``PK`` and the key exchange keys ``KEK`` control who may
change those databases.

Most distributions boot through shim, a small first-stage loader
signed by Microsoft's UEFI certificate authority. shim carries the
distribution's certificate and verifies the next stage against it and
against the Machine Owner Key (MOK) list, which the machine's owner
enrolls through shim's ``MokManager``. This lets an owner sign their
own kernels or unified kernel images without changing the firmware's
databases.

Secure Boot verifies executables, not the data they load. A boot
loader that reads a kernel and a separate initrd file passes the
initrd to the kernel unchecked, and a command line typed at the boot
menu is not signed by anyone. That gap is the reason for unified
kernel images.

Unified kernel images
---------------------

A unified kernel image (UKI) is one PE executable that bundles the
``systemd-stub`` boot stub with the kernel (``.linux``), the initrd
(``.initrd``), the command line (``.cmdline``) and further sections
such as ``.osrel``, ``.uname`` and ``.sbat``. The firmware or shim
verifies the whole file once, so the signature covers the initrd and
the command line together with the kernel.

When Secure Boot is enabled and the UKI has a ``.cmdline`` section,
``systemd-stub`` ignores any command line a boot loader passes to
it. The command line that reaches the kernel is then exactly the
signed one.

Kernel command line
-------------------

The command line configures the kernel before any userspace runs, and
some parameters change security properties. ``lsm=``, for example,
selects which LSMs run, and a list without ``bpf`` leaves no BPF LSM
for shirudo to attach to. shirudo needs two parameters of its own:
``bpf.keyring_unsealed=1`` and ``dm_verity.keyring_unsealed=1``. They
leave the kernel's ``.bpf`` and ``.dm-verity`` keyrings open until
``shirudo init`` enrolls its certificates and seals them, see
:doc:`keyrings`. Whoever can edit the command line at the boot menu
can change all of this, so the parameters belong in the UKI's
``.cmdline`` section, where Secure Boot covers them and PCR 11 records
them.

Measured boot
-------------

A TPM has a set of platform configuration registers (PCRs). A PCR
cannot be written, only extended: the TPM replaces its value with the
hash of the old value and a new digest. Each boot stage hashes the
next stage, or a piece of configuration, and extends a PCR with the
result before handing over. Because extension is ordered and one-way,
the final value of a PCR commits to every measurement and to their
order, and no later code can bring back an earlier value. Only a new
TPM startup, at a reboot or a resume from hibernation, returns them to
their initial values.
:doc:`tpm` explains PCRs and banks in more detail.

A PCR value alone says little. Each measuring component also appends
an entry to an event log, and a verifier replays the log to check that
it produces the quoted PCR value and then judges the entries. The logs
are not protected; the PCRs are what make them trustworthy. Linux
exposes the firmware's log, which also holds what the boot loader and
the kernel's EFI stub measured before the kernel took over, at
``/sys/kernel/security/tpm0/binary_bios_measurements``. systemd keeps
its userspace log at ``/run/log/systemd/tpm2-measure.log``.

Table 1 lists the common assignments on a Linux system that boots a
UKI. The TCG PC Client firmware profile defines PCRs 0 to 7. The
Linux TPM PCR Registry of the UAPI group lists what Linux components
use, and systemd's documentation of its measurements gives the
details.

.. list-table:: Table 1. PCR assignments relevant to shirudo
   :header-rows: 1
   :widths: 10 30 60

   * - PCR
     - Measured by
     - What
   * - 0-3
     - Firmware
     - Firmware code and configuration, option ROMs and their data.
   * - 4
     - Firmware, shim
     - Each UEFI executable started: shim, the boot loader, the UKI.
   * - 5
     - Firmware, ``systemd-boot``
     - The GPT partition table; ``systemd-boot``'s ``loader.conf``.
   * - 7
     - Firmware, shim
     - The Secure Boot state and the certificates used; shim adds its
       own certificates and SBAT data.
   * - 8
     - GRUB
     - GRUB commands and the kernel command line, when GRUB boots.
   * - 9
     - Kernel EFI stub, GRUB, systemd, shirudo
     - The initrd and the command line the kernel's EFI stub receives;
       files GRUB reads; systemd's NvPCR anchors and separators;
       shirudo's anchor.
   * - 10
     - IMA
     - The IMA measurement list, when IMA is enabled.
   * - 11
     - ``systemd-stub``, ``systemd-pcrphase``
     - Every section of the UKI except ``.pcrsig``; the boot phase
       strings.
   * - 12
     - ``systemd-stub``
     - A command line passed in place of ``.cmdline``, credentials,
       configuration extensions and add-ons.
   * - 13
     - ``systemd-stub``
     - System extension images for the initrd.
   * - 14
     - shim
     - The MOK list.
   * - 15
     - systemd
     - The machine ID, file system identities and LUKS volume keys.

The kernel's own PCR 9 measurements are made by its EFI stub, in
``drivers/firmware/efi/libstub/efi-stub-helper.c``. It extends PCR 9
with the command line, when it is not empty, as
``LOADED_IMAGE::LoadOptions``, and then with the initrd as a tagged
event ``Linux initrd``.

Boot phases in PCR 11
---------------------

PCR 11 is predictable. ``systemd-stub`` measures only the UKI's
sections into it, so a vendor can compute its value from the UKI file
alone. systemd then extends it at fixed points of the boot with phase
strings: ``enter-initrd``, ``leave-initrd``, ``sysinit``, ``ready``,
``shutdown`` and ``final``, in this order.
``systemd-pcrphase-initrd.service`` extends ``enter-initrd`` when it
starts, early in the initrd, and ``leave-initrd`` when it stops, right
before the switch to the root file system.

So the value PCR 11 holds while the initrd runs exists only in the
initrd. Once ``leave-initrd`` is measured, nothing can bring that
value back before the next TPM reset. A TPM object whose policy
requires that value can be used from the initrd and from nowhere else.
``systemd-measure calculate --phase=enter-initrd`` computes the value
from the UKI.

systemd makes these phase measurements only when the kernel was
started by ``systemd-stub`` from a UKI. A kernel and initrd that a
boot loader or QEMU loads separately leave PCR 11 without them.

NvPCRs
------

A PC Client TPM has 24 PCRs, and most of them have an owner. systemd
259 and later add NvPCRs: TPM NV indices of the extend type, which
behave like PCRs but are allocated from NV index space and defined by
``/usr/lib/nvpcr/*.nvpcr`` files. An NV index can be deleted and
recreated by anyone who satisfies the owner authorization, which is
often empty, so systemd protects an NvPCR in two ways.

Its write policy allows the first write only from the initrd, through
a policy on PCR 11, and later writes need no further authorization.
And ``systemd-tpm2-setup-early.service`` extends PCR 9 with the
index's name as ``nvpcr-init:<name>:0x<handle>:<tpm-name>``, so a
recreated index with other attributes or another policy has a name
that does not match the one PCR 9 recorded.
``systemd-pcrnvdone.service`` then extends PCR 9 with
``nvpcr-separator`` to mark the end of the initializations. From
systemd 261 on, ``systemd-pcrosseparator.service`` extends PCR 9 and
other PCRs with ``os-separator`` before any of this, early in the
initrd.

shirudo's measurement register follows this construction with one
important difference: every write, not only the first, needs a
signature from a TPM-held key and is checked by an LSM hook.
:doc:`tpm` describes it.

How shirudo uses the boot chain
-------------------------------

A production target boots a UKI whose initrd carries the shirudo
bootstrap binary, ``shirudo-initrd.service`` and the bootstrap
settings, including ``runtime.image`` and ``runtime.root_hash``, the
expected root hash of the dm-verity runtime image. Its ``.cmdline``
carries the two keyring parameters. The dracut module and
``shirudo-gen-initrd`` build the initrd, see :doc:`initrd-dracut`.
shirudo does not build or sign the UKI.

The boot chain gives shirudo an authenticated starting point. Secure
Boot ensures the initrd and command line are the signed ones, and the
root hash in the initrd's settings then authenticates the runtime
image, see :doc:`dm-verity`. shirudo itself does not check the Secure
Boot state. It relies on the deployment to enable Secure Boot, and a
verifier can check PCR 7 in the evidence. Kernel lockdown it does not
need: from ``init`` on, its own programs refuse what lockdown in
integrity mode refuses, see :doc:`/operate/plan/hardening`.

Figure 1 shows where shirudo's run falls among these measurements.
``shirudo-initrd.service`` orders itself after the units that measure
``enter-initrd`` and the NvPCR anchors and before the switch to the
root file system, so ``init`` binds its measurement register to the
values PCRs 9 and 11 hold inside that window and then extends PCR 9
with its own anchor. ``shirudo.service`` adopts the record in the root
file system without another TPM extension. :doc:`tpm` explains the
binding, and :doc:`/internals/boot-flow` gives the whole sequence.

.. figure:: /images/background-boot-pcrs.svg
   :alt: A timeline of the boot with two lanes, PCR 9 and PCR 11.
         systemd-stub measures the UKI sections into PCR 11, and the
         kernel's EFI stub the command line and the initrd into PCR 9.
         In the initrd, PCR 11 receives enter-initrd and leave-initrd,
         and between the two it holds the value the register can be
         bound under. Into PCR 9 go os-separator, the nvpcr-init
         anchors, shirudo's anchor from shirudo-initrd and
         nvpcr-separator from systemd-pcrnvdone, the last two in either
         order. After the switch root, shirudo.service extends nothing,
         and PCR 11 receives sysinit and ready.

   Figure 1. PCR 9 and PCR 11 during the boot of a UKI. Unit names
   leave out ``systemd-`` and ``.service`` where systemd ships them.

A remote verifier ties all of this together. ``shirudo attest`` quotes
PCRs 0 to 7, 9 and 11 to 15 by default, and the operator pins the PCR 9
and PCR 11 values the register was bound under with
``--expect-bind-pcr``, computing the PCR 11 value from the UKI. See
:doc:`/operate/run/attest`.

Limits
------

- Without a UKI booted through ``systemd-stub``, PCR 11 holds no phase
  measurement. ``init`` warns, and only PCR 9 can tell an initrd
  binding from a later one.
- Measured boot records and does not prevent. A host booted with
  another UKI, or one where the initrd run of ``init`` failed, still
  comes up. Only a verifier that compares the quoted PCRs and the
  register binding with approved values notices. The
  :doc:`/security/threat-model` describes the fail-open boot.
- Any process that can send TPM commands can extend PCR 9 after
  shirudo's anchor, and ``systemd-pcrnvdone.service`` may (Figure 1).
  The anchor check in ``attest verify`` then is a note, and
  ``--strict-anchor`` turns it into a failure.
- The evidence carries the firmware and systemd event logs, but
  ``attest verify`` does not replay them. It compares the PCR values
  the operator pins with ``--expect-pcr`` and ``--expect-bind-pcr``.

Related
-------

- :doc:`tpm` for PCRs, NV indices and the register binding
- :doc:`initrd-dracut` for the initrd shirudo runs from
- :doc:`/internals/boot-flow` for the initrd and root runs of ``init``
- :doc:`/operate/deploy/boot-integration` to set up the boot of a target
- `TPM2 PCR Measurements Made by systemd
  <https://systemd.io/TPM2_PCR_MEASUREMENTS/>`__
- `UAPI.7 Linux TPM PCR Registry
  <https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/>`__
- `UAPI.5 Unified Kernel Image
  <https://uapi-group.org/specifications/specs/unified_kernel_image/>`__
