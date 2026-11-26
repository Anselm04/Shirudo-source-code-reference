..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

dm-verity
=========

shirudo runs from a read-only image whose every block the kernel checks
against a single trusted hash, and it reads its configuration from a
second image checked the same way. This page explains how dm-verity does
that, where the trusted hash comes from, and what dm-verity does not
protect.

Why signed files are not enough
-------------------------------

The binary that enforces the policy must be the one the operator built.
On a writable file system, root can replace it, edit a configuration file
beside it or swap a library underneath it. A signature checked when a
file is opened covers the bytes at that moment, and nothing ties later
reads to them.

What we want is a device on which no block can differ from what the
operator built, checked each time the kernel reads a block from it.

A hash tree over the device
---------------------------

dm-verity is a read-only device-mapper target. It combines a data device
with a hash device. The data device is divided into blocks, 4096 bytes in
shirudo's images, and the digest of each block is stored on the hash
device. The digests are packed into hash blocks, those blocks are hashed
in turn, and so on until one block remains. The digest of that block,
with a salt, is the root hash. Figure 1 shows a small tree.

.. figure:: /images/background-dm-verity-tree.svg
   :alt: A hash tree with a root hash over two hash blocks, four hash
         blocks below them and eight data blocks at the bottom. The path
         from data block D5 through H2 and H23 to the root is highlighted.

   Figure 1. A hash tree over eight data blocks, two children per node to
   keep the figure small. With SHA-256 and 4096-byte blocks, one hash
   block holds 128 digests. Changing D5 changes H2, H23 and the root
   hash.

The kernel does not hash the whole device up front. When a data block is
read from the device, dm-verity hashes it and checks the digest against
its hash block, then that hash block against the level above, up to the
root. A hash block that has passed once is remembered as verified, so
later reads stop there. If the chain does not end at the root hash the
device was set up with, the read fails. One trusted value therefore
vouches for every byte of the image.

Corruption handling
-------------------

By default a block that fails verification makes the read fail with
``EIO``. The kernel logs ``<data-device>: data block <n> is corrupted``
and sends a uevent, and from then on the device status reports the
corruption. Table options can instead only log the corruption
(``ignore_corruption``), restart the machine (``restart_on_corruption``)
or panic (``panic_on_corruption``). Optional forward error correction
can repair a block, which dm-verity then checks against its hash before
using it.

Where the root hash comes from
------------------------------

dm-verity does not decide which root hash is the right one. The kernel
expects whoever sets up the device to have been authenticated already.
There are two common ways to make a root hash trusted, and shirudo uses
both.

The first takes the root hash from something already trusted. shirudo's
runtime image, which holds its executables, gets its root hash from the
bootstrap settings in the initrd. In production, that initrd is part of
the unified kernel image, which Secure Boot verifies and the boot chain
measures into the TPM before the kernel runs (see :doc:`boot`).

The second signs the root hash. The table option
``root_hash_sig_key_desc`` names a key of type ``user`` that holds a
PKCS#7 signature over the root hash as it appears in the table, a string
of hexadecimal digits. The kernel verifies the signature when the table
is loaded, before the device can be used. It tries the keyrings in this
order (see :doc:`keyrings`):

#. the builtin trusted keyring, or the secondary trusted keyring, which
   includes it, when the kernel is built with
   ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING``;
#. the platform keyring, when the kernel is built with
   ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING``, which
   defaults to the value of the secondary option;
#. the ``.dm-verity`` keyring, once it holds a key and is restricted.

The kernel moves to the next keyring only when the previous one has no
matching key or rejects the signature. The first keyring that verifies
the signature admits the table.

A table without a signature still loads unless the kernel was booted
with ``dm_verity.require_signatures=1``. Whether a mapping was signed is
therefore a property of that mapping. dm-verity reports each device's
root hash and signature state to the LSMs through the
``bdev_setintegrity`` hook before the device goes live.

What shirudo adds
-----------------

shirudo sets up its mappings itself through the device-mapper ioctls,
without a userspace tool on the target: version 1 format, 4096-byte
data and hash blocks, SHA-256 and a salt, with the image files attached
to read-only loop devices. For a configuration image it first verifies
the root hash signature against the runtime image's config
certificates, then adds ``root_hash_sig_key_desc`` and loads the
signature into a ``user`` key in its thread keyring, so that the kernel
checks it again. It then reads back the table the kernel holds and
checks it.

Because dm-verity checks a block only when it is read, a corrupted
block would surface only when something happens to read it, possibly
halfway through applying a configuration. shirudo reads every data block
of a new runtime or configuration mapping once, with direct I/O, before
it mounts the image, parses its content or extends the configuration
PCR. A corrupted image fails before any of its content is used: a live
update is refused and the active configuration stays, and at boot init
fails.

shirudo's ``lsm.s/bdev_setintegrity`` program ties mappings to roots. A
mapping counts as the runtime only if its root hash equals the one frozen
from the bootstrap settings, and as a configuration only if its root
matches the one a task with runtime authority staged for it. A mount of
any other verity device gains neither status. ``shirudo init`` enrolls
the configuration verification certificate in ``.dm-verity`` and seals
it. See :doc:`/internals/config-images`.

Limits
------

dm-verity protects blocks on their way from the device into memory.
Pages already in memory, process memory, anonymous mappings and code
injected into a running task are outside its reach.

dm-verity does not decide which correctly signed root is current. An
older configuration image with a valid signature passes its check.
Choosing the active image is up to shirudo's configuration updates; see
:doc:`/internals/config-images`.

The kernel accepts a signature from any key in the keyrings it consults,
not only from ``.dm-verity``. On a kernel whose builtin, secondary or
platform keyring holds other keys, such as a distribution's module
signing key, those keys pass the kernel's check of a configuration
root. They do not pass shirudo's own check before it, which admits only
the config certificates (assumption A7 of the
:doc:`/security/threat-model`).
