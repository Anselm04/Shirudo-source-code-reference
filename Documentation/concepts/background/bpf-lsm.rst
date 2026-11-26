..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

BPF LSM
=======

File permissions and capabilities decide most access checks in Linux,
and root passes nearly all of them. A policy that must hold against root
needs a check that runs inside the kernel, at the operation itself, and
that root cannot turn off. Linux security modules (LSMs) provide those
checks, and the BPF LSM lets BPF programs act as one. This page explains
the parts of the LSM framework shirudo builds on.

LSM hooks
---------

The kernel calls into the LSM framework at fixed points: before a file is
opened (``file_open``), before an inode is unlinked (``inode_unlink``),
at the entry of the ``bpf()`` system call (``bpf``), before a key is used
(``key_permission``), and at a few hundred other places. Each such call
site is a hook. A hook passes the objects involved, such as the file,
the inode or the key, and most hooks return an integer: ``0`` allows the
operation, a negative error number refuses it, and the system call fails
with that error.

A hook can only refuse what reaches it. An operation the kernel routes
past every hook cannot be denied by any LSM; ``mount_setattr(2)``, for
example, calls no LSM hook.

Stacking and order
------------------

Several LSMs can be active at once: SELinux or AppArmor, Yama, Landlock,
IMA, the BPF LSM and others. For each hook, the kernel calls every active
LSM that implements it, in order, and stops at the first one that
returns a refusal. The capability checks always run first, and IMA and
EVM always run last.

The order of the others comes from ``CONFIG_LSM`` or, if given, the
``lsm=`` kernel parameter, which overrides it. An LSM that is built in
but missing from that list does not run. ``/sys/kernel/security/lsm``
lists the active LSMs of the running kernel.

Because the first refusal ends the walk, an LSM placed late in the list
does not see an operation that an earlier one already refused.

For a shirudo target, the most minimal and ideal setting is ``lsm=bpf``,
which enables the BPF LSM alone; the capability checks still run first,
and IMA and EVM, when built in, still run last. No other LSM then
refuses an operation before shirudo's programs see and count it, and
on an upstream kernel without the carried xattr patch none can hide a
seal label by refusing the read of it (see :doc:`/security/threat-model`).
The security code the target runs shrinks to what shirudo uses.
Lockdown is an LSM as well, and shirudo's ``bpf2`` object refuses what
its integrity mode refuses from ``init`` on, so the target needs no
lockdown LSM. Where one runs, a kernel built with
``CONFIG_SECURITY_LOCKDOWN_LSM_EARLY`` starts it before it reads the
list, so ``lsm=bpf`` keeps it, and it decides before shirudo.

BPF programs on LSM hooks
-------------------------

With ``CONFIG_BPF_LSM`` and ``bpf`` in the active list, the BPF LSM
registers an empty default function for nearly every hook. A program of
type ``BPF_PROG_TYPE_LSM`` attaches to one of these through a BPF
trampoline, with ``BPF_RAW_TRACEPOINT_OPEN`` or ``BPF_LINK_CREATE``, and
then runs whenever the kernel calls that hook. In source, the section
name names the hook, as in ``SEC("lsm/file_open")``. The kernel refuses
programs whose license is not GPL-compatible, and a small set of hooks
takes no BPF programs at all.

If ``bpf`` is missing from the active list, the kernel never calls the
BPF LSM's functions, so programs attached there never run.

On a hook that returns an integer, a program receives the hook's
arguments plus one more, ``ret``: the value the previous BPF program on
the same hook returned, or ``0`` for the first. By convention, a program
that sees a non-zero ``ret`` returns it unchanged, so that one refusal is
not overwritten by a later program.

Return values
-------------

The verifier restricts what an LSM program may return. For a hook that
returns an integer, the program returns ``0`` or a negative error number.
A few hooks return a boolean, and the program returns ``0`` or ``1``. A
hook that returns nothing, such as ``bprm_committed_creds``, only
observes; its program cannot refuse anything and is used to record
state.

Sleepable hooks
---------------

Some hooks run where the kernel may sleep. A program attached to one of
them with the ``lsm.s/`` section prefix is loaded as sleepable and may
call kfuncs that sleep, such as the ones that read extended attributes
(see :doc:`xattrs`). The kernel keeps a list of the hooks that accept
sleepable programs and refuses the ``lsm.s/`` form on any other hook.

Task and inode storage
----------------------

An LSM program often needs to remember something about a kernel object:
that a task has some authority, or that an inode carries some label. Two
map types attach that state to the object itself. A
``BPF_MAP_TYPE_TASK_STORAGE`` map holds one value per task, and a
``BPF_MAP_TYPE_INODE_STORAGE`` map one value per in-memory inode.

The value lives as long as the object. It is freed when the task exits,
or when the inode leaves the inode cache, even if the file still exists
on disk. Inode storage needs the BPF LSM to be active at boot; without it
the kernel refuses to create such a map.

Kernel argument of the bpf hook
-------------------------------

The ``bpf`` hook runs at the entry of every ``bpf()`` call. Its last
argument, ``kernel``, is ``true`` when the call came from inside the
kernel rather than from a userspace process. That is the case for calls a
signed loader makes through the ``bpf_sys_bpf()`` helper (see
:doc:`bpf`) and for BPF that kernel code loads itself. The
``bpf_prog_load`` and ``bpf_map_create`` hooks carry the same argument.

This one bit lets a policy close ``bpf()`` to userspace while leaving it
open to code that is already inside the kernel: the loader passed the
policy's checks when userspace loaded it, so what it does next does not
have to pass them again.

How shirudo uses the BPF LSM
----------------------------

shirudo's enforcement is two BPF objects of LSM programs, ``bpf2`` and
``seal``, embedded in the binary. ``shirudo init`` checks that ``bpf``
appears in ``/sys/kernel/security/lsm`` (preflight check
``bpf_lsm_active``), loads both objects, attaches every program and pins
the links in its private bpffs.

``bpf2`` gates BPF itself. Its ``lsm/bpf`` program returns ``0`` at once
when ``kernel`` is set; for userspace callers it admits only a signed
loader's ``BPF_PROG_LOAD``, the commands the signed-loader pattern needs
from a task with runtime authority, and read-only commands, and refuses
every other command. ``lsm/bpf_prog_load`` checks the signature verdict
(see :doc:`bpf-signing`). Further ``bpf2`` programs guard, among other
things, the private bpffs and its mount, the kernel keyrings, the
device-mapper controls and the TPM.

``seal`` protects writable state and decides which tasks have runtime
authority. A task gains it by a successful exec of a binary from the
verified runtime image. A ``BPF_MAP_TYPE_TASK_STORAGE`` map records the
mark, ``lsm/task_alloc`` passes it to children, and the void hook
``lsm.s/bprm_committed_creds`` commits or clears it after each exec. A
``BPF_MAP_TYPE_INODE_STORAGE`` map caches the seal label of the inodes
the seal read it from. Many seal programs are sleepable because they
read extended attributes.

See :doc:`/internals/enforcement` for the inventory of hooks and
:doc:`/internals/seal` for the seal.

Limits
------

The BPF LSM refuses only what reaches its hooks. Operations without a
hook, and access to the machine below the kernel, are outside it. When
an earlier LSM in the list refuses an operation, shirudo's program for
that hook does not run, so the refusal moves none of shirudo's tamper
counters. Inode storage is lost when an inode leaves the cache, which is
why the seal's marks are a cache its hooks refresh from the label and
never the decision. :doc:`/security/threat-model` lists the residual
risks.
