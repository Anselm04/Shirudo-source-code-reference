..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Kernel keyrings
===============

When the kernel verifies a signature, over a module, a BPF loader or a
dm-verity root hash, it needs a public key it trusts. The kernel keeps
such keys in keyrings. Which keyring a check consults, and who may change
that keyring, decides what the signature is worth. This page explains
keyrings in general, the ones the kernel uses for signatures, and how
shirudo sets up and protects its two.

Keys and keyrings
-----------------

A key is a kernel object with a serial number (a positive 32-bit
integer), a type, a description, a payload, an owner, a group and a
permission mask. A keyring is a key of type ``keyring`` whose payload is
a list of links to other keys, keyrings included. Keys of type
``asymmetric`` hold public keys; adding an X.509 certificate creates one
whose description the kernel derives from the certificate.

Userspace manages keys with the ``add_key(2)`` and ``keyctl(2)`` system
calls. ``/proc/keys`` lists the keys the reading task may view.

Links and nested keyrings
-------------------------

A keyring does not contain keys; it links to them. The same key can be
linked from several keyrings at once, and unlinking it from one leaves
it in the others. The kernel destroys a key only when no link and no
reference to it remain. A keyring indexes its links by type and
description, so linking a second key with the same type and description
replaces the first.

A link can point at a key of any type, and that includes another
keyring. A link in a keyring is therefore not always a key. The system
keyrings below are built that way: ``.secondary_trusted_keys`` links
``.builtin_trusted_keys`` and, when configured, ``.machine``.

Nesting matters for signatures. To verify a signature against a keyring,
the kernel searches that keyring and, recursively, every keyring linked
from it. A key reachable through a nested keyring is therefore trusted
like one linked directly. Reading a keyring with ``keyctl(2)``, however,
returns only its direct links. A nested keyring shows up as one link
with its own serial and type, not as the keys behind it. To know what a
keyring trusts, every link has to be followed, whatever its type;
counting the asymmetric keys at the top level is not enough.

The description is the only identity the kernel shows for a public key,
because the key material never leaves the kernel. For a key made from an
X.509 certificate, the description is ``<subject>: <id>``. The subject
is the certificate's common name (CN), written as ``<O>: <CN>`` when the
certificate also names an organization (O) that the CN does not already
start with, and the O or the email address when there is no CN. The id
is the hex subject key identifier, or the serial number when the
certificate has none. To tell which certificate a key holds, one compares that
description with the one the certificate would get.

Special keyring ids
-------------------

Besides serial numbers, the system calls accept negative special ids that
name a keyring relative to the caller, such as
``KEY_SPEC_THREAD_KEYRING`` (``-1``), ``KEY_SPEC_PROCESS_KEYRING``
(``-2``) and ``KEY_SPEC_SESSION_KEYRING`` (``-3``).
``KEY_SPEC_BPF_KEYRING`` (``-9``) names the kernel's ``.bpf`` keyring
directly, so its serial does not have to be looked up first. Kernels
that provide ``KEY_SPEC_DM_VERITY_KEYRING`` (``-10``) name ``.dm-verity``
the same way; shirudo requires it (see
:doc:`/operate/plan/system-requirements`).

Permissions and possession
--------------------------

The permission mask has six bits for each of four classes: possessor,
user (the owner), group and other. The bits are view, read, write,
search, link and set attribute. Write permission on a keyring allows
adding and removing links. Set attribute allows changing the
permissions and applying a restriction.

A task possesses a key when it can reach the key from its own thread,
process or session keyring, and the possessor bits then apply to it.
``KEY_SPEC_BPF_KEYRING`` hands out a reference that is not possessed, so
for the ``.bpf`` keyring only the user, group and other bits count. Both
``.bpf`` and ``.dm-verity`` are owned by root and grant their owner view,
read, write, search and set attribute. Any root process can therefore
add keys to them, remove keys and restrict them.

Restrictions
------------

``KEYCTL_RESTRICT_KEYRING`` attaches a restriction to a keyring. The
kernel checks the restriction for every new link: a key type and a
restriction string can, for example, admit only keys signed by a trusted
key. Without a type, the keyring rejects every new link with ``-EPERM``.

A keyring takes one restriction for its lifetime: a second attempt fails
with ``-EEXIST``, and none can be lifted. A restriction bounds what can
be added, never what can be taken away. A task with write permission can
still unlink a key from a restricted keyring, clear it or revoke it.

System keyrings
---------------

The kernel builds several keyrings at boot for its own signature checks:

``.builtin_trusted_keys``
    Certificates compiled into the kernel image, such as the module
    signing key.

``.secondary_trusted_keys``
    Links the builtin keyring and, when configured, ``.machine``. It
    accepts further keys at run time only if a key it already trusts
    vouches for them (``CONFIG_SECONDARY_TRUSTED_KEYRING``).

``.machine``
    Machine Owner Keys (MOK), when the kernel is built with
    ``CONFIG_INTEGRITY_MACHINE_KEYRING``.

``.platform``
    Keys the firmware provides, such as the UEFI signature database.

A key in these keyrings is trusted for everything that consults them,
and Figure 1 below shows how much that is: module signatures, kexec
images and dm-verity root hashes all search them. That breadth is why
the kernel adds keyrings scoped to one purpose.

Purpose-specific keyrings
-------------------------

The ``.bpf`` keyring holds keys for BPF program signatures (see
:doc:`bpf-signing`). The ``.dm-verity`` keyring holds keys for
dm-verity root hash signatures (see :doc:`dm-verity`). Both follow the
same rules:

- The kernel creates them at boot, sealed and empty, unless the boot
  parameter ``bpf.keyring_unsealed=1`` or ``dm_verity.keyring_unsealed=1``
  leaves the keyring open so that the initrd can provision it. Both
  parameters are read-only once the system runs.
- The kernel consults the keyring only once it is non-empty and
  restricted. An open keyring is ignored even when it holds keys.
- Provisioning ends with a restriction. Until then, anything that may
  write the keyring can add keys to it.

The two differ in how a check reaches them. ``BPF_PROG_LOAD`` searches
the one keyring its ``keyring_id`` names, and shirudo's
``lsm/bpf_prog_load`` admits only a signature that ``.bpf`` verified.
dm-verity searches ``.dm-verity`` last, after the system keyrings
(Figure 1).

.. figure:: /images/background-keyring-search.svg
   :alt: The keyrings .builtin_trusted_keys, .secondary_trusted_keys,
         which links the builtin keyring and .machine, .platform, and
         .bpf and .dm-verity, which init seals. A module signature
         searches the secondary keyring; a kexec image the secondary,
         then the platform keyring; BPF_PROG_LOAD the one keyring its
         keyring_id names, of which lsm/bpf_prog_load admits only .bpf;
         a dm-verity root hash the builtin or secondary keyring, then
         the platform keyring if configured, then .dm-verity once
         sealed.

   Figure 1. Which keyrings each of the kernel's signature checks
   searches, in order.

How shirudo enrolls and seals the keyrings
------------------------------------------

``shirudo init`` provisions both keyrings from the initrd, before the
root file system's services start (see :doc:`/internals/boot-flow`).

For ``.bpf``, init adds each certificate of the boot trust set: the
initial certificate from the runtime image and every certificate the
selected signed configuration vouches for. It then seals the keyring with
``KEYCTL_RESTRICT_KEYRING`` and no type, and checks that the keyring
holds exactly that set. Every link counts, whatever its type, because the
kernel's search also enters a nested keyring. For ``.dm-verity``, init
adds the configuration verification certificate from the runtime image,
seals the keyring and checks that it holds that certificate and nothing
else.

``shirudo init`` refuses a keyring it did not seal itself. For a
keyring sealed empty because the boot lacked the parameter, it says to
boot with the parameter. A keyring that another task restricted first,
or that holds keys beyond the set, is refused as well.

Init then records the serials of both keyrings, of the ``.dm-verity``
key and of the enrolled ``.bpf`` keys in a frozen map. Later commands
compare the ``.bpf`` serial with that record and refuse ``tampered`` on
a mismatch. ``shirudo status`` compares both keyrings with it and
follows every link, whatever its type: a swapped or missing keyring, a
link ``init`` did not record or a missing config key makes its verdict
``tampered`` (see :doc:`/operate/run/read-status`). shirudo's
``lsm/key_permission`` program refuses write, set
attribute and unlink on the recorded keyrings and keys to every task
without runtime authority, and refuses a search through an unpossessed
reference, which is how ``keyctl`` reaches a key by serial. The
refusals count as ``KeyringWrite``. The kernel's own signature checks
search through a possessed reference and are unaffected.

A signed configuration activated at run time can revoke an enrolled
key, which unlinks it. Nothing adds a key to either keyring until the
next boot, and key changes made locally on the target are refused. See
:doc:`/operate/maintain/keys` and :doc:`/internals/enforcement`.

Limits
------

Until init seals them, the keyrings accept a key from any root process
in the initrd. Init detects such a key by its exact-set check and
refuses, but it cannot remove it. The initrd itself has to be
authenticated, which production targets do through the boot chain.

A restriction does not stop removal. Between the seal and the attachment
of ``lsm/key_permission``, which both happen within init, a root process
could unlink a key and take signed loading out until the next boot.

For dm-verity, ``.dm-verity`` is consulted only after the builtin
keyring and, when configured, the secondary and platform keyrings, so a
key there passes the kernel's check of a configuration root as well.
shirudo's own check against the runtime image's config certificates
refuses it; see :doc:`dm-verity`.
