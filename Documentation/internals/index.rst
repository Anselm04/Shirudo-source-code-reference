..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Internals
=========

How shirudo works inside the kernel and on a target, and why it is built
this way: the signed loader path, the LSM programs and the seal, the
boot sequence, the measurement register, the images, and the kernel
interfaces and patches it depends on. These pages are for kernel
developers and security reviewers who need to judge the design.
Operators do not need them to run shirudo; :doc:`/security/threat-model`
states what the mechanisms here defend against and where they stop.

.. toctree::
   :titlesonly:

   architecture
   signed-loader
   enforcement
   seal
   boot-flow
   measurement-register
   config-images
   kernel-interfaces
   kernel-patches
   design-decisions
