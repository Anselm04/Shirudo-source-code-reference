..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

initrd, initramfs and dracut
============================

Before the kernel can mount the root file system, it may need drivers,
storage setup or decryption that live on that very file system. A small
file system in memory, the initramfs, breaks the circle. It is also the
first userspace that runs, before anything from the root file system,
which is why shirudo brings up its enforcement there. This page explains
the initramfs, systemd's role in it and how dracut builds it, then how
shirudo uses all three.

What the initramfs is
---------------------

The kernel always has a root file system of its own, rootfs, an instance
of tmpfs or ramfs. At boot it unpacks a cpio archive into it: the one
linked into the kernel image, which is usually empty, and the one the
boot loader passes in, which distributions build. Files from the passed
archive replace files of the same name from the built-in one.

If rootfs then contains ``/init``, the kernel runs it as process 1. That
program is responsible for the rest of the boot, including finding and
mounting the real root file system. Without ``/init``, the kernel tries
to mount a root partition itself.

The older initrd mechanism loaded a file system image onto a RAM block
device. Today the word initrd usually names the archive the boot loader
passes in, and tools use both words for it. This documentation says
initrd.

Switching to the real root
--------------------------

The init program in the initrd mounts the real root file system, usually
at ``/sysroot``, then switches to it. It carries the mounts of ``/dev``,
``/proc``, ``/sys`` and ``/run`` over into the new root, makes the new
root ``/``, frees the initrd's files and executes the real init.

Processes started from the initrd are not meant to survive the switch,
and systemd kills them. What has to survive lives in the kernel or below
``/run``: keyrings, loaded modules, TPM state, and BPF links held by pins
in a bpffs mounted under ``/run``.

systemd in the initrd
---------------------

An initrd can run systemd as its init, and shirudo's initrd does. The
file ``/etc/initrd-release`` tells systemd that it runs in an initrd. It
then mounts the root file system at ``/sysroot`` (``sysroot.mount``),
reaches ``initrd-root-fs.target`` and ``initrd.target``, and finally
switches root through ``initrd-switch-root.target`` and
``initrd-switch-root.service``. A unit ordered after
``initrd-root-fs.target`` and before ``initrd.target`` runs with the root
file system mounted but not yet in charge. On the switch, systemd carries
``/run``, with the mounts below it, into the new root.

On a measured boot, ``systemd-pcrphase-initrd.service`` measures the
word ``enter-initrd`` into PCR 11 when it starts and ``leave-initrd``
when it stops at the switch. PCR 11 therefore differs between the initrd
and the root file system. See :doc:`boot` and :doc:`tpm`.

dracut
------

dracut builds the initrd from the installed system. It copies binaries
with the libraries they need, kernel modules and configuration into a
staging directory, then archives and compresses it, usually to the
distribution's initrd path, such as ``/boot/initramfs-<release>.img``.
``lsinitrd`` lists what an initrd holds.

dracut is built from modules. Each module is a directory under
``/usr/lib/dracut/modules.d/``, named with a two-digit order and a name,
whose ``module-setup.sh`` defines up to four functions:

``check()``
    Decides whether the module is included: ``0`` includes it, ``1``
    leaves it out, ``255`` includes it only when another module depends
    on it or the configuration or command line asks for it.

``depends()``
    Names the modules this one needs.

``installkernel()``
    Installs kernel modules.

``install()``
    Installs everything else: binaries, files and systemd units.

The ``systemd`` module makes systemd the initrd's init. ``dracut.conf(5)``
files and dracut's command line choose the modules and set variables
that modules read.

In production, the initrd is packed together with the kernel and its
command line into a unified kernel image (UKI). Secure Boot verifies the
UKI as a whole, and the boot measures it into the TPM, so the initrd's
content is authenticated before any of it runs. See :doc:`boot`.

How shirudo uses the initrd
---------------------------

shirudo ships a dracut module, ``90shirudo``, from
:src:`tools/gen-initrd/module-setup.sh`. Its ``check()`` looks for the
``shirudo`` binary and the primary certificate. It depends on the
``systemd`` and ``systemd-initrd`` modules, and on
``systemd-pcrextend`` (``systemd-pcrphase`` in older dracut releases)
and ``tpm2-tss`` when their checks pass. It installs the TPM drivers
(``tpm``, ``tpm_tis_core``, ``tpm_tis``, ``tpm_crb``) and the drivers for
the images (``dm_mod``, ``dm_verity``, ``loop``, ``ext4``). Its
``install()`` copies:

- the ``shirudo`` binary, at the path it has on the root file system;
- the primary certificate as ``/etc/shirudo/keys/cert.der``, and the
  further trusted certificates with their vouches under
  ``/etc/shirudo/keys/trusted/``;
- the bootstrap settings as ``/etc/shirudo/shirudo.conf``, which name the
  runtime image and its root hash;
- the ``mount`` tool, with which the unit remounts ``/sysroot``;
- ``shirudo-initrd.service``, enabled for ``initrd.target``.

``shirudo-gen-initrd`` runs dracut with this module, checks the result
with ``lsinitrd`` and prints the kernel parameters the initrd needs,
``bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1``. See
:doc:`/operate/deploy/boot-integration` for the procedure.

``shirudo-initrd.service`` runs ``shirudo init`` after
``initrd-root-fs.target`` and ``systemd-pcrphase-initrd.service``, and
before ``initrd.target`` and the switch. It remounts ``/sysroot``
read-write first. init runs here for three reasons:

- The ``.bpf`` and ``.dm-verity`` keyrings are open from boot until
  someone restricts them. Enrolling and sealing them in the initrd closes
  them before anything from the root file system runs (see
  :doc:`keyrings`).
- The measurement register can be bound only while PCR 11 still holds
  the value of the ``enter-initrd`` phase, which no later process can
  bring back (see :doc:`/concepts/measurement-register`).
- The LSM programs are attached before any service of the root file
  system starts.

init checks that ``/`` is tmpfs or ramfs and refuses otherwise. It binds
``/sysroot/var/lib/shirudo`` at ``/var/lib/shirudo``, writable, so that
the state paths are the same as on the root file system, and releases
the bind when it exits. Its mounts and pins live under ``/run/shirudo``,
which systemd carries across the switch. On the root file system,
``shirudo.service`` runs ``init`` again from the verified runtime image
and adopts what the initrd run recorded. See :doc:`/internals/boot-flow`.

Limits
------

``shirudo-initrd.service`` is wanted by ``initrd.target`` and has no
failure action. If init fails, the boot continues without enforcement,
and ``shirudo status`` and attestation are what reveal it. The unit is
also skipped when the initrd holds no certificate. The threat model lists
this under threats to resolve: :doc:`/security/threat-model`.

Everything that runs in the initrd before the unit runs as root, without
shirudo's enforcement. The initrd is trustworthy only as far as the boot
chain authenticates it, which is why production targets boot a signed
UKI.

When ``shirudo-gen-initrd`` receives any of ``--cert``,
``--trusted-dir``, ``--binary``, ``--unit`` or ``--bootstrap-conf``, it
runs dracut with a configuration of its own, and dracut then ignores the
host's ``/etc/dracut.conf`` and ``/etc/dracut.conf.d``.
